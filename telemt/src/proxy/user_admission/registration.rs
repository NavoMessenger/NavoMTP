use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use parking_lot::MutexGuard;
use tokio_util::sync::CancellationToken;

use super::*;

/// Authority lock retained until the caller publishes its owned object.
pub(crate) struct UserAdmissionPublication<'a> {
    /// Locked authority state that linearizes publication with policy mutation.
    pub(super) state: MutexGuard<'a, UserAdmissionState>,
    /// Process authority used by the eventual registration guard.
    pub(super) authority: Arc<UserAdmissionAuthority>,
    /// Username owning the published lifecycle object.
    pub(super) user: String,
    /// Unique registration identity within the process authority.
    pub(super) registration_id: u64,
    /// User incarnation authenticated by this publication.
    pub(super) incarnation: UserIncarnation,
    /// Revocation signal shared with the lifecycle owner.
    pub(super) token: CancellationToken,
    /// Atomic publication state shared with the registration guard.
    pub(super) active: Arc<AtomicU8>,
    /// Whether ownership has already moved into a registration guard.
    pub(super) registration_taken: bool,
}

impl UserAdmissionPublication<'_> {
    /// Moves the registered owner out while retaining the authority lock.
    pub(crate) fn take_registration(&mut self) -> Option<UserSessionRegistration> {
        if self.registration_taken {
            return None;
        }
        self.registration_taken = true;
        Some(UserSessionRegistration {
            authority: Arc::clone(&self.authority),
            user: self.user.clone(),
            registration_id: self.registration_id,
            incarnation: self.incarnation,
            token: self.token.clone(),
            active: Arc::clone(&self.active),
        })
    }

    /// Commits the owner record after the caller publishes its lifecycle object.
    pub(crate) fn commit(mut self) {
        if !self.registration_taken {
            return;
        }
        if self
            .active
            .compare_exchange(
                REGISTRATION_PENDING,
                REGISTRATION_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        self.state
            .owners_by_user
            .entry(self.user.clone())
            .or_default()
            .insert(
                self.registration_id,
                RegisteredOwner {
                    token: self.token.clone(),
                    incarnation: self.incarnation,
                },
            );
    }
}

/// RAII ownership registered against one user incarnation.
#[must_use = "registered user ownership must be retained until lifecycle completion"]
pub(crate) struct UserSessionRegistration {
    authority: Arc<UserAdmissionAuthority>,
    user: String,
    registration_id: u64,
    incarnation: UserIncarnation,
    token: CancellationToken,
    active: Arc<AtomicU8>,
}

impl UserSessionRegistration {
    /// Returns the cancellation signal for revocation or credential replacement.
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Returns the immutable user incarnation owned by this registration.
    pub(crate) fn incarnation(&self) -> UserIncarnation {
        self.incarnation
    }

    /// Returns whether revocation has cancelled this ownership.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Drop for UserSessionRegistration {
    fn drop(&mut self) {
        if self.active.swap(REGISTRATION_DROPPED, Ordering::AcqRel) == REGISTRATION_ACTIVE {
            self.authority
                .unregister(&self.user, self.registration_id, self.incarnation);
        }
    }
}
