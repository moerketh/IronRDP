//! Guest-side Enhanced Session backend: **X.224 only — no TLS, no CredSSP**.
//!
//! Hyper-V Enhanced Session Mode has two connection seams, and this module implements
//! the second one:
//!
//! 1. `vmconnect.exe` connects to the host's vmms service on [`PORT`](crate::PORT) and
//!    performs **PCB → TLS → CredSSP → X.224**. That front-end is implemented on the
//!    client side by [`connect_front`](crate::connect_front).
//! 2. vmms then relays into the guest, where the guest's own RDP server listens on an
//!    AF_HYPERV/AF_VSOCK socket. vmms has already terminated TLS and authenticated the
//!    user on the front-end, and hands the guest a **plaintext** RDP byte stream. The
//!    relayed client still performs the X.224 exchange, but the guest must not attempt
//!    a TLS upgrade or a CredSSP exchange of its own: there is no TLS record layer on
//!    this transport and no second CredSSP conversation to have.
//!
//! xrdp's Hyper-V backend describes the same seam as "Security handled by host: do
//! nothing."
//!
//! # Security
//!
//! [`accept_begin_host_relayed`] deliberately performs no authentication and no
//! encryption. It is sound only when the transport is itself the proof of identity —
//! an AF_HYPERV/AF_VSOCK listener that only the hosting hypervisor can reach. Routing
//! a listener that untrusted peers can reach through this function accepts anonymous,
//! unencrypted RDP sessions.

use core::time::Duration;

use ironrdp_acceptor::Acceptor;
use ironrdp_async::{Framed, FramedRead, FramedWrite, single_sequence_step};
use ironrdp_connector::{ConnectorResult, general_err, reason_err};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::SecurityProtocol;
use tracing::{instrument, warn};

/// Upper bound for completing the X.224 exchange on a host-relayed connection.
///
/// [`accept_begin_host_relayed`] blocks on the peer's Connection Request. A peer
/// that connects and then sends nothing would otherwise park that read forever —
/// and because an [`Acceptor`] is driven with `&mut`, a server handling one
/// connection at a time is wedged for as long as the silent peer holds the
/// socket open. Measured on a Hyper-V guest 2026-08-27: a single blank
/// connection blocked the listener for 13.5 minutes, leaving real vmms
/// connections un-accepted in the backlog.
///
/// This crate stays runtime-agnostic; async callers should enforce the deadline
/// around [`accept_begin_host_relayed`] (for example with `tokio::time::timeout`).
///
/// Ten seconds mirrors [`PCB_TRANSMIT_DEADLINE`](crate::PCB_TRANSMIT_DEADLINE),
/// the equivalent bound MS-RDPEPS places on the client's preconnection PDU.
pub const HOST_RELAY_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// Require a negotiated protocol whose security upgrade this path may skip.
///
/// The Connection Confirm has just promised the peer a particular protocol, and
/// [`accept_begin_host_relayed`] then declines to perform it. That is only
/// coherent when the peer is not going to start one either:
///
/// - `HYBRID` / `HYBRID_EX` — what vmms negotiates. CredSSP already happened on
///   the host's front-end connection with `vmconnect.exe`, so the relayed stream
///   carries none of it.
/// - empty — the server advertised no enhanced security, so nothing follows.
///
/// `SSL` means the peer expects TLS records immediately after the Confirm.
/// Skipping the handshake desynchronises the stream, and the failure surfaces
/// much later as an unintelligible decode error somewhere in MCS. Refusing here
/// turns a confusing mid-sequence failure into a clear configuration error.
///
/// This is the server-side counterpart of
/// [`ensure_selected_credssp`](crate::ensure_selected_credssp).
pub fn ensure_host_relayable(protocol: SecurityProtocol) -> ConnectorResult<()> {
    if protocol.is_empty() || protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
        Ok(())
    } else {
        Err(reason_err!(
            "vmconnect",
            "host-relayed transport cannot skip the {protocol} upgrade promised by the Connection              Confirm; a Hyper-V Enhanced Session negotiates HYBRID or HYBRID_EX",
        ))
    }
}

/// Run the X.224 exchange for a host-relayed Enhanced Session connection, then skip
/// the security upgrade the acceptor would otherwise expect.
///
/// Drives `acceptor` until it has answered the client's Connection Request with a
/// Connection Confirm, marks the security upgrade — and the CredSSP exchange it
/// implies for `HYBRID`/`HYBRID_EX` — as already done, and returns the same
/// [`Framed`] for [`accept_finalize`](ironrdp_acceptor::accept_finalize).
///
/// Returning the `Framed` rather than the raw stream is load-bearing. vmms pipelines
/// the MCS Connect Initial into the same segment as the X.224 Connection Request, so
/// by the time the Connection Confirm goes out those bytes are already buffered.
/// [`accept_begin`](ironrdp_acceptor::accept_begin) hands back
/// `BeginResult::ShouldUpgrade(stream)` via `Framed::into_inner_no_leftover`, which
/// discards them; the client then hangs waiting for a Connect Response that the
/// server is waiting to be asked for.
///
/// Callers should bound this with [`HOST_RELAY_HANDSHAKE_DEADLINE`]; a peer that
/// connects and sends nothing otherwise blocks the caller indefinitely.
///
/// # Security
///
/// This skips authentication as well as encryption. See the [module
/// documentation](self#security) for when that is acceptable.
#[instrument(level = "trace", skip_all)]
pub async fn accept_begin_host_relayed<S>(mut framed: Framed<S>, acceptor: &mut Acceptor) -> ConnectorResult<Framed<S>>
where
    S: FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();

    loop {
        if acceptor.reached_security_upgrade().is_some() {
            // Deliberately not `reached_security_upgrade`'s return value: that is
            // the protocol set the server was *configured* with, not the single
            // protocol negotiated in the Connection Confirm.
            let protocol = acceptor
                .negotiated_protocol()
                .ok_or_else(|| general_err!("no negotiated protocol at the security upgrade"))?;

            ensure_host_relayable(protocol)?;

            warn!(
                ?protocol,
                "Host-relayed transport: skipping TLS and CredSSP. This connection is                  NOT authenticated and NOT encrypted by this server; the vsock peer                  allowlist is the only access control."
            );

            acceptor.mark_security_upgrade_as_done();

            // `mark_security_upgrade_as_done` lands in `Credssp` when the negotiated
            // protocol is HYBRID or HYBRID_EX, and in `BasicSettingsWaitInitial`
            // otherwise. Only the former needs a second transition.
            if acceptor.should_perform_credssp() {
                acceptor.mark_credssp_as_done();
            }

            return Ok(framed);
        }

        single_sequence_step(&mut framed, acceptor, &mut buf).await?;
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_connector::DesktopSize;
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, RequestFlags};
    use ironrdp_pdu::x224::X224;
    use ironrdp_tokio::TokioFramed;

    use super::*;

    /// Bytes vmms puts on the wire right after the Connection Request. The exact
    /// content does not matter here; what matters is that they arrive in the same
    /// segment and must survive into `accept_finalize`.
    const PIPELINED: &[u8] = &[0x03, 0x00, 0x00, 0x2c, 0x02, 0xf0, 0x80];

    fn connection_request(protocol: SecurityProtocol) -> Vec<u8> {
        encode_vec(&X224(ConnectionRequest {
            nego_data: None,
            flags: RequestFlags::empty(),
            protocol,
            correlation_info: None,
        }))
        .expect("encode connection request")
    }

    fn acceptor(security: SecurityProtocol) -> Acceptor {
        Acceptor::new(
            security,
            DesktopSize {
                width: 1024,
                height: 768,
            },
            Vec::new(),
            None,
        )
    }

    /// Drive one host-relayed handshake and return `(acceptor, leftover, server_reply)`.
    async fn handshake(security: SecurityProtocol, requested: SecurityProtocol) -> (Acceptor, Vec<u8>, Vec<u8>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (mut client, server) = tokio::io::duplex(4096);

        // One write: Connection Request immediately followed by the next PDU, which
        // is what makes the leftover land in the acceptor's read buffer.
        let mut pipelined = connection_request(requested);
        pipelined.extend_from_slice(PIPELINED);
        client.write_all(&pipelined).await.expect("client write");

        let mut acceptor = acceptor(security);
        let framed = accept_begin_host_relayed(TokioFramed::new(server), &mut acceptor)
            .await
            .expect("host-relayed accept must succeed");

        let leftover = framed.get_inner().1.to_vec();

        let mut reply = vec![0u8; 19];
        let n = client.read(&mut reply).await.expect("client read");
        reply.truncate(n);

        (acceptor, leftover, reply)
    }

    /// The bytes vmms pipelines behind the Connection Request must still be there
    /// for `accept_finalize`. Handing back the inner stream instead of the `Framed`
    /// drops them, and the connection then hangs: the client waits for a Connect
    /// Response the server is still waiting to be asked for.
    #[tokio::test]
    async fn keeps_bytes_pipelined_behind_the_connection_request() {
        let (_acceptor, leftover, _reply) = handshake(SecurityProtocol::HYBRID, SecurityProtocol::HYBRID).await;
        assert_eq!(leftover, PIPELINED, "pipelined PDU must survive into accept_finalize");
    }

    /// What vmms actually negotiates, plus the no-enhanced-security case, must
    /// pass: nothing follows the Connection Confirm on the wire in either.
    #[test]
    fn host_relayable_accepts_what_vmms_negotiates() {
        for ok in [
            SecurityProtocol::HYBRID,
            SecurityProtocol::HYBRID_EX,
            SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX,
            SecurityProtocol::empty(),
        ] {
            assert!(ensure_host_relayable(ok).is_ok(), "{ok} should be relayable");
        }
    }

    /// A protocol whose handshake the peer will actually start cannot be skipped.
    #[test]
    fn host_relayable_refuses_protocols_that_expect_a_handshake() {
        for bad in [SecurityProtocol::SSL, SecurityProtocol::RDSTLS] {
            assert!(
                ensure_host_relayable(bad).is_err(),
                "{bad} promises a handshake this path does not perform"
            );
        }
    }

    /// End to end: a TLS-only server reached over the host-relayed path fails with
    /// a clear error at the Connection Confirm, rather than skipping a handshake
    /// the peer is about to start and desynchronising somewhere inside MCS.
    #[tokio::test]
    async fn tls_only_server_is_refused_on_the_host_relayed_path() {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tokio::io::duplex(4096);
        client
            .write_all(&connection_request(SecurityProtocol::SSL))
            .await
            .expect("client write");

        let mut acceptor = acceptor(SecurityProtocol::SSL);
        // `Framed` is not Debug, so `expect_err` is unavailable here.
        let err = match accept_begin_host_relayed(TokioFramed::new(server), &mut acceptor).await {
            Ok(_) => panic!("SSL must not be silently skipped"),
            Err(e) => e,
        };

        let rendered = format!("{err}");
        assert!(
            rendered.contains("HYBRID") || rendered.contains("host-relayed"),
            "error should explain the mismatch, got: {rendered}"
        );
    }

    /// REGRESSION (measured 2026-08-27): a peer that connects and sends nothing
    /// parks this function's first read. Because an `Acceptor` is driven with
    /// `&mut`, a server handling one connection at a time is wedged for as long
    /// as that peer holds the socket — one blank connection blocked a live
    /// listener for 13.5 minutes while real vmms connections sat un-accepted.
    ///
    /// This pins the property that makes [`HOST_RELAY_HANDSHAKE_DEADLINE`]
    /// load-bearing: the function blocks, so the *caller* must bound it. If this
    /// ever starts returning on its own, the constant and its docs are stale.
    #[tokio::test]
    async fn silent_peer_blocks_until_the_caller_gives_up() {
        // `_client` must stay bound: dropping the near end closes the duplex, the
        // read returns EOF, and the function would fail fast — testing nothing.
        let (_client, server) = tokio::io::duplex(4096);

        let mut acceptor = acceptor(SecurityProtocol::HYBRID);
        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            accept_begin_host_relayed(TokioFramed::new(server), &mut acceptor),
        )
        .await;

        assert!(
            outcome.is_err(),
            "a silent peer must block; only the caller's deadline ends it"
        );
    }

    /// After the X.224 exchange the acceptor must be past both the security upgrade
    /// and CredSSP, so `accept_finalize` reads the MCS Connect Initial next rather
    /// than waiting for a TLS ClientHello that will never come.
    #[tokio::test]
    async fn leaves_no_pending_security_upgrade_or_credssp() {
        let server = SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX;
        for requested in [SecurityProtocol::HYBRID, SecurityProtocol::HYBRID_EX] {
            let (acceptor, _leftover, _reply) = handshake(server, requested).await;
            assert!(
                acceptor.reached_security_upgrade().is_none(),
                "{requested:?}: security upgrade still pending"
            );
            assert!(
                !acceptor.should_perform_credssp(),
                "{requested:?}: CredSSP still pending"
            );
        }
    }

    /// The client still gets a well-formed Connection Confirm; only the upgrade that
    /// would follow it is skipped.
    #[tokio::test]
    async fn answers_the_client_with_a_connection_confirm() {
        let (_acceptor, _leftover, reply) = handshake(SecurityProtocol::HYBRID, SecurityProtocol::HYBRID).await;

        let confirm: X224<ConnectionConfirm> = ironrdp_core::decode(&reply).expect("client must get a Confirm");
        let ConnectionConfirm::Response { protocol, .. } = confirm.0 else {
            panic!("expected a Response, got {:?}", confirm.0);
        };
        assert_eq!(protocol, SecurityProtocol::HYBRID);
    }

    /// `RdpServerSecurity::None` negotiates no upgrade at all. The acceptor still
    /// passes through `SecurityUpgrade` with an empty protocol, and no CredSSP
    /// transition applies.
    #[tokio::test]
    async fn handles_a_server_configured_without_enhanced_security() {
        let (acceptor, leftover, _reply) = handshake(SecurityProtocol::empty(), SecurityProtocol::empty()).await;
        assert!(acceptor.reached_security_upgrade().is_none());
        assert!(!acceptor.should_perform_credssp());
        assert_eq!(leftover, PIPELINED);
    }
}
