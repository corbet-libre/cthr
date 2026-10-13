//! Initial living-room MLS state from the original consented Groups decision.
use super::*;

impl Threads {
    /// Create the initial Opening/Public MLS group from the complete consented
    /// roster. The genuine Groups decision includes seed/opening authority and
    /// profile-visibility consent. Outputs require the existing shared Groups
    /// and Threads checkpoint before release.
    ///
    /// This is genesis, not an external join or an Assembly ordering receipt.
    /// Later joins must use the ordered member-side room protocol.
    pub async fn create_room(
        &self,
        keys: &mut impl Custody,
        decision: &cgrp::PreparedEffect<'_>,
        packages: &[Vec<u8>],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        self.create_membership(keys, decision, packages, clock, true)
            .await
    }

    /// Accept the original genesis Welcome only when its signed MLS context and
    /// exact certified roster match this same authenticated Groups decision.
    /// A Welcome cannot import an arbitrary claimed room or authorize a later
    /// join. The local conversation must still be empty.
    pub async fn join_room(
        &self,
        keys: &mut impl Custody,
        decision: &cgrp::PreparedEffect<'_>,
        welcome: &[u8],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        self.join_membership(keys, decision, welcome, clock, true)
            .await
    }
}
