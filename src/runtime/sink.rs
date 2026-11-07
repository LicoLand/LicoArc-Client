//! The caller's endpoint-side [`PacketSink`]: one [`InboundSession`] per lane.
//!
//! Every claimed packet goes through the SDK's own verification entry
//! (`receive_record`, `inbound.rs`): a committed record completes the station
//! item, a refused record releases it back to the claim window, and the
//! caller's staged-secret source supplies the per-record bootstrap handle the
//! SDK may need. The sink decides no verdict of its own — the SDK commits or
//! refuses, and the settlement mirrors that fact.

use licoarc::endpoint::{Endpoint, EndpointState, Role};
use licoarc::error::Error;
use licoarc::provider::Provider;
use licoarc::state::{
    AtomicState, KeyCustody, PendingId, PlaintextReceiver, StagedSecretHandle, X25519Private,
};

use crate::inbound::{InboundRefusal, InboundSession, TrustFacts};
use crate::runtime::mailbox::{ConsumeVerdict, PacketSink};

/// Supplies the optional staged bootstrap secret for the next record.
///
/// The caller owns custody and knows whether the current session phase needs
/// a fresh private per record; a session that never bootstraps returns
/// `None`.
pub trait FreshPrivate {
    fn next(&mut self) -> Option<StagedSecretHandle<X25519Private>>;
}

impl<F> FreshPrivate for F
where
    F: FnMut() -> Option<StagedSecretHandle<X25519Private>>,
{
    fn next(&mut self) -> Option<StagedSecretHandle<X25519Private>> {
        self()
    }
}

/// A session that never needs a staged bootstrap secret.
pub struct NoFreshPrivate;

impl FreshPrivate for NoFreshPrivate {
    fn next(&mut self) -> Option<StagedSecretHandle<X25519Private>> {
        None
    }
}

/// One claimed packet, authenticated and committed by the SDK.
#[derive(Debug)]
pub struct Received {
    /// The session's own facts extended by this exact record.
    pub facts: TrustFacts,
    /// The durable pending identity of the committed record; the caller
    /// releases its plaintext and settles it with this id.
    pub pending: PendingId,
}

/// A packet the SDK refused to commit, with its refusal.
#[derive(Debug)]
pub struct Refused {
    /// The SDK's own refusal for that exact packet.
    pub refusal: InboundRefusal,
}

/// A [`PacketSink`] that feeds one [`InboundSession`].
///
/// `accept` calls `receive_record` once and reports the outcome verbatim:
/// committed records land in [`SessionSink::received`] and complete the item,
/// refusals land in [`SessionSink::refused`] and release it. The settlement
/// never invents a verdict the SDK did not reach.
pub struct SessionSink<'a, P, C, S, F> {
    session: &'a mut InboundSession<P, C, S>,
    fresh: F,
    received: Vec<Received>,
    refused: Vec<Refused>,
}

impl<'a, P, C, S, F> SessionSink<'a, P, C, S, F>
where
    P: licoarc::provider::Provider,
    C: KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
    F: FreshPrivate,
{
    /// Feeds records to `session`; `fresh` supplies the staged bootstrap
    /// secret per record.
    pub fn new(session: &'a mut InboundSession<P, C, S>, fresh: F) -> Self {
        Self {
            session,
            fresh,
            received: vec![],
            refused: vec![],
        }
    }

    /// Records committed this pump, in claim order.
    #[must_use]
    pub fn received(&self) -> &[Received] {
        &self.received
    }

    /// Packets the SDK refused this pump, in claim order.
    #[must_use]
    pub fn refused(&self) -> &[Refused] {
        &self.refused
    }
}

impl<P, C, S, F> PacketSink for SessionSink<'_, P, C, S, F>
where
    P: licoarc::provider::Provider,
    C: KeyCustody,
    S: licoarc::state::AtomicState<licoarc::endpoint::EndpointState>,
    F: FreshPrivate,
{
    fn accept(&mut self, packet: &[u8]) -> ConsumeVerdict {
        match self.session.receive_record(packet, self.fresh.next()) {
            Ok((facts, pending)) => {
                self.received.push(Received { facts, pending });
                ConsumeVerdict::Complete
            }
            Err(refusal) => {
                self.refused.push(Refused { refusal });
                ConsumeVerdict::Release
            }
        }
    }
}

/// A [`PacketSink`] that feeds one bare endpoint — the session a drive serves
/// directly after a resume, without an [`InboundSession`] wrapper.
///
/// Same settlement vocabulary as [`SessionSink`]: the SDK's `receive_record`
/// commits or refuses; a committed record's plaintext is released to
/// `receiver` through `release_pending_plaintext`, which settles the durable
/// pending item only after the caller's boundary reports success. A record
/// that committed but could not release is still `Complete` — it lives in
/// the committed pending set and the next drain re-drives it.
pub struct EndpointSink<'a, R: Role, P, C, S, T> {
    endpoint: &'a mut Endpoint<R, P, C, S>,
    receiver: T,
    received: Vec<PendingId>,
    refused: Vec<Error>,
}

impl<'a, R, P, C, S, T> EndpointSink<'a, R, P, C, S, T>
where
    R: Role,
    P: Provider,
    C: KeyCustody,
    S: AtomicState<EndpointState>,
    T: PlaintextReceiver,
{
    /// Feeds records to `endpoint`; `receiver` takes each released plaintext.
    pub fn new(endpoint: &'a mut Endpoint<R, P, C, S>, receiver: T) -> Self {
        Self {
            endpoint,
            receiver,
            received: vec![],
            refused: vec![],
        }
    }

    /// Records committed this pump, in claim order.
    #[must_use]
    pub fn received(&self) -> &[PendingId] {
        &self.received
    }

    /// Packets the SDK refused this pump, in claim order.
    #[must_use]
    pub fn refused(&self) -> &[Error] {
        &self.refused
    }
}

impl<R, P, C, S, T> PacketSink for EndpointSink<'_, R, P, C, S, T>
where
    R: Role,
    P: Provider,
    C: KeyCustody,
    S: AtomicState<EndpointState>,
    T: PlaintextReceiver,
{
    fn accept(&mut self, packet: &[u8]) -> ConsumeVerdict {
        match self.endpoint.receive_record(packet, None) {
            Ok(pending) => {
                self.received.push(pending);
                // Release is the durable half of the commit: a failed release
                // leaves the pending item for the next drain, and the station
                // item still completes because the record was committed.
                let _ = self
                    .endpoint
                    .release_pending_plaintext(pending, &mut self.receiver);
                ConsumeVerdict::Complete
            }
            Err(error) => {
                self.refused.push(error);
                ConsumeVerdict::Release
            }
        }
    }
}
