//! Station-reported transport hints, kept read-only.
//!
//! A station reports exactly these booleans: a lease, an acceptance flag, a
//! duplicate flag, or a deletion acknowledgement is an untrusted transport
//! hint and cannot establish endpoint evidence. This type carries that hint
//! into the peer-message record without ever turning it into a fact.

/// One station-reported delivery hint.
///
/// It is intentionally inert: there is no conversion from this type to a
/// delivery, admission, read, or acceptance fact, and [`Self::is_endpoint_evidence`]
/// is a constant `false` so no caller can read it as one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StationHint {
    station_reported_accepted: bool,
    station_reported_duplicate: bool,
}

impl StationHint {
    /// Records what the station reported, verbatim.
    #[must_use]
    pub const fn reported(
        station_reported_accepted: bool,
        station_reported_duplicate: bool,
    ) -> Self {
        Self {
            station_reported_accepted,
            station_reported_duplicate,
        }
    }

    /// Nothing reported yet.
    #[must_use]
    pub const fn none() -> Self {
        Self::reported(false, false)
    }

    #[must_use]
    pub const fn station_reported_accepted(self) -> bool {
        self.station_reported_accepted
    }

    #[must_use]
    pub const fn station_reported_duplicate(self) -> bool {
        self.station_reported_duplicate
    }

    /// Always `false`: a station hint is never endpoint evidence.
    #[must_use]
    pub const fn is_endpoint_evidence(self) -> bool {
        false
    }
}
