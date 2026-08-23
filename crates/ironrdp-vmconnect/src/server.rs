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

use ironrdp_acceptor::Acceptor;
use ironrdp_async::{Framed, FramedRead, FramedWrite, single_sequence_step};
use ironrdp_connector::ConnectorResult;
use ironrdp_core::WriteBuf;
use tracing::{debug, instrument};

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
        if let Some(protocol) = acceptor.reached_security_upgrade() {
            debug!(?protocol, "Host-relayed transport: skipping TLS upgrade and CredSSP");

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
    use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, RequestFlags, SecurityProtocol};
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
