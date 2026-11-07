//! Session and interaction policy stubs.
//!
//! Closed enums only. Transition tables and native presence workflows belong
//! to a later node.

/// Legal client session states. App lock defaults off; an unlocked device
/// session supports ordinary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSessionState {
    DeviceUnlocked,
    AppLocked,
    Terminated,
}

/// Runtime-facing client session. No host or Flutter field can override state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSession {
    state: ClientSessionState,
}

impl ClientSession {
    pub fn device_unlocked() -> Self {
        Self {
            state: ClientSessionState::DeviceUnlocked,
        }
    }

    pub fn app_locked() -> Self {
        Self {
            state: ClientSessionState::AppLocked,
        }
    }

    pub fn terminated() -> Self {
        Self {
            state: ClientSessionState::Terminated,
        }
    }

    pub fn state(self) -> ClientSessionState {
        self.state
    }

    pub fn allows_ordinary_interaction(self) -> bool {
        matches!(self.state, ClientSessionState::DeviceUnlocked)
    }
}

/// Confirmation class computed by Rust from the trusted use-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationRequirement {
    None,
    Review,
    FreshUserPresence,
}

/// Authentication class computed together with confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationRequirement {
    None,
    NativeUserPresence,
}

/// Combined confirmation and authentication requirement for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationPolicy {
    pub confirmation: ConfirmationRequirement,
    pub authentication: AuthenticationRequirement,
}

impl OperationPolicy {
    pub fn ordinary_direct() -> Self {
        Self {
            confirmation: ConfirmationRequirement::None,
            authentication: AuthenticationRequirement::None,
        }
    }

    pub fn requires_fresh_user_presence(self) -> bool {
        matches!(
            self.confirmation,
            ConfirmationRequirement::FreshUserPresence
        ) || matches!(
            self.authentication,
            AuthenticationRequirement::NativeUserPresence
        )
    }
}
