#![allow(dead_code)]
use cgrp::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;

pub fn members(start: usize, end: usize) -> BTreeSet<String> {
    (start..end).map(|i| format!("m{i}")).collect()
}

// These are signed fixture parameters, not a production resolution of the
// pending band/split decisions. Both legal vector interpretations are tested.
pub fn policy() -> Policy {
    let edges = [3, 6, 9, 13, 20, 30, 43, 60, 80];
    let posts = [120, 90, 60, 40, 30, 24, 18, 12, 8];
    let bursts = [20, 15, 12, 10, 8, 6, 5, 4, 3];
    let notifications = [
        Notification::EveryMessage,
        Notification::QuietHours,
        Notification::SilentReactions,
        Notification::MentionsReplies,
        Notification::MentionsRepliesDigest,
        Notification::MentionsDigest,
        Notification::MentionsDaily,
        Notification::MentionsDaily,
        Notification::ContactsWeekly,
    ];
    Policy {
        epoch: 1,
        valid_until: 1_000 * DAY,
        cap: 100,
        circle_max: 12,
        ingroup_max: 42,
        shrink_public: 36,
        shrink_ingroup: 10,
        open_seconds: 21 * DAY,
        fork_cooldown: 14 * DAY,
        retarget_cooldown: 28 * DAY,
        listing_wait: 72 * 3_600,
        split_public_min: 43,
        bands: std::array::from_fn(|i| Band {
            lower: edges[i],
            enter_up: edges[i],
            leave_down: edges[i] - 2,
            notification: notifications[i],
            posts_per_hour: posts[i],
            burst: bursts[i],
            vouches: if i == 5 {
                2
            } else if (3..5).contains(&i) {
                1
            } else {
                0
            },
            history_seconds: [0, 0, 0, 14 * DAY, 7 * DAY, 3 * DAY, DAY, DAY / 2, DAY / 4][i],
            history_messages: [0, 0, 0, 200, 200, 200, 100, 50, 50][i],
            joins_per_hour: if i >= 7 { Some(6) } else { None },
        }),
        seats: SeatFormats {
            enabled: false,
            refill_per_day: 1.0,
            capacity: 10.0,
            initial: 5.0,
            minimum: 0.25,
            small: 1.5,
            large: 3.0,
            low: 7,
            high: 60,
            tau: 1.0,
            epoch_days: 7,
            quantum: 0.5,
            warning_days: 2,
        },
        suggest_at: 66,
        pressure_at: 85,
        modularity: 0.3,
        overlap: 0.4,
        suggestion_cooldown: 7 * DAY,
        decline_cooldown: 14 * DAY,
        reciprocity_enabled: true,
        welcome_quarters: 1,
        introduction_quarters: 4,
        week_cap_quarters: 6,
    }
}

pub struct SignedPolicy {
    community: String,
    bytes: Vec<u8>,
    signature: [u8; 64],
    key: [u8; 32],
}
impl SignedPolicy {
    pub fn new(p: &Policy) -> Self {
        Self::for_community("alpha", p)
    }
    pub fn for_community(community: &str, p: &Policy) -> Self {
        let key = SigningKey::from_bytes(&[230; 32]);
        let bytes = serde_json::to_vec(p).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        Self {
            community: community.into(),
            bytes,
            signature,
            key: key.verifying_key().to_bytes(),
        }
    }
    pub fn corrupt(&mut self) {
        self.signature[0] ^= 1;
    }
}
impl PolicySource for SignedPolicy {
    fn current(&self, community: &str, _: u64) -> Result<Policy> {
        if community != self.community {
            return Err(Error::Authority);
        }
        ckmg::verify_ed25519(&self.key, &self.bytes, &self.signature)
            .map_err(|_| Error::Authority)?;
        serde_json::from_slice(&self.bytes).map_err(|_| Error::Policy)
    }
}

pub struct TestAuthority;
fn signer(member: &str) -> SigningKey {
    // Synthetic test registry, not device/G3 authority or a production adapter.
    SigningKey::from_bytes(ckmg::hash(member.as_bytes()).value())
}
impl Authority for TestAuthority {
    fn consent(&self, c: &Consent, _: u64) -> Result<()> {
        let signature: [u8; 64] = c
            .signature
            .clone()
            .try_into()
            .map_err(|_| Error::Authority)?;
        ckmg::verify_ed25519(
            &signer(&c.member).verifying_key().to_bytes(),
            &c.signing_bytes()?,
            &signature,
        )
        .map_err(|_| Error::Authority)
    }
    fn contact(&self, _: &str, member: &str, contact: &str, _: u64) -> Result<()> {
        // This isolated fixture's contact graph is complete over m0..m199.
        if [member, contact].iter().all(|s| {
            s.strip_prefix('m')
                .and_then(|s| s.parse::<usize>().ok())
                .is_some_and(|n| n < 200)
        }) {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
}

pub fn request(
    state: &Snapshot,
    command: Command,
    actor: &str,
    consenters: BTreeSet<String>,
    visible: bool,
    now: u64,
) -> Request {
    let mut r = Request {
        operation: *ckmg::hash(&state.revision().to_le_bytes()).value(),
        parents: state.parent_references(&command).unwrap_or_default(),
        effective_at: now,
        actor: actor.into(),
        command,
        consents: vec![],
    };
    for member in consenters {
        let mut c = Consent {
            community: state.community().into(),
            member,
            operation: r.operation,
            policy_epoch: 1,
            command_digest: r.command_digest().unwrap(),
            profile_visibility: visible,
            key_package: vec![],
            lineage_handle: vec![],
            valid_until: now + DAY,
            signature: vec![],
            authority: vec![],
        };
        c.signature = signer(&c.member)
            .sign(&c.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        r.consents.push(c);
    }
    r
}

/// Memory-only durable store: applies every candidate and keeps the last one.
#[derive(Default)]
pub struct Keep(pub Option<Snapshot>);
impl Persistence for Keep {
    fn commit<'a>(
        &'a mut self,
        _: u64,
        candidate: &'a Snapshot,
        _: &'a [Effect],
    ) -> CommitFuture<'a> {
        Box::pin(async move {
            self.0 = Some(candidate.clone());
            Ok(Commit::Applied)
        })
    }
}

/// The two hidden groups every room grows out of (the product has no seed
/// rooms): a circle `[1; 32]` of twelve, extended by consent to the in-group
/// `[2; 32]` of thirteen. All twelve and thirteen members consent, none shows a
/// profile. Rooms are then opened with `open_room`.
pub async fn open_base(source: &SignedPolicy) -> Snapshot {
    let empty = Snapshot::empty("alpha".into());
    let circle = request(
        &empty,
        Command::Create {
            id: [1; 32],
            members: members(0, 12),
        },
        "m0",
        members(0, 12),
        false,
        500,
    );
    let mut keep = Keep::default();
    let (state, _) = prepare(&empty, &circle, source, &TestAuthority, 1000, 10)
        .unwrap()
        .persist(&mut keep, 1000)
        .await
        .unwrap();
    let grow = request(
        &state,
        Command::Fork {
            id: [2; 32],
            parents: vec![[1; 32]],
            members: members(0, 13),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 13),
        false,
        600,
    );
    prepare(&state, &grow, source, &TestAuthority, 1000, 10)
        .unwrap()
        .persist(&mut keep, 1000)
        .await
        .unwrap()
        .0
}

/// The request that opens room `id` with the first three members of the base
/// in-group (the three who consent to be seen), effective at `at`.
pub fn open_room(base: &Snapshot, id: Id, at: u64) -> Request {
    request(
        base,
        Command::Fork {
            id,
            parents: vec![[2; 32]],
            members: members(0, 3),
            kind: ForkKind::Open,
        },
        "m0",
        members(0, 3),
        true,
        at,
    )
}

/// Put `base` into a device's durable store as its accepted Groups snapshot,
/// as the checkpoint of a device that already took part in the base groups.
pub async fn install_base(store: &mut cwst::Store<cwst::backend::Memory>, base: &Snapshot) {
    let version = store.version().unwrap();
    let bytes = postcard::to_allocvec(base).unwrap();
    store
        .commit(
            version,
            [250; 32],
            &[cwst::Change::Put {
                owner: "cgrp",
                key: b"snapshot.v1",
                value: &bytes,
            }],
            &[],
        )
        .await
        .unwrap();
}
