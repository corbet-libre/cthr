use super::*;
use csgn::{Kind, SecretKey, Signer};
use serde_json::{Value, json};

pub struct Published {
    pub charter: cchr::Charter,
    signer: Signer,
    schema: cshm::Schema,
    revision: u64,
    pub until: u64,
    pub now: u64,
}
impl Published {
    pub fn new() -> Self {
        let signer =
            Signer::new("alpha", SecretKey::from_seed(&mut [71; 32]), 1000, 10000).unwrap();
        let charter = cchr::Charter::new(cchr::Configuration {
            origin: ORIGIN.into(),
            community: "alpha".into(),
            key_ring: signer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        })
        .unwrap();
        let schema = serde_json::from_value(json!({
            "community":"alpha", "version":1,
            "public":[{"id":"bio","label":"Bio","kind":{"type":"short_text","min_length":0,"max_length":100},
                "required":true,"filterable":false,"change_preset":"free","no_contact_details":true}],
            "private":[]
        })).unwrap();
        let mut value = Self {
            charter,
            signer,
            schema,
            revision: 0,
            until: 1400,
            now: NOW,
        };
        value.install(2, &[], &[]);
        value
    }
    fn sign(&mut self, kind: Kind, payload: Value) -> Vec<u8> {
        self.signer
            .sign(
                kind,
                &serde_json::to_vec(&payload).unwrap(),
                1000,
                self.until,
            )
            .unwrap()
    }
    pub fn install(&mut self, epoch: u64, members: &[String], devices: &[[u8; 32]]) {
        self.revision += 1;
        let revision = self.revision;
        let schema = serde_json::to_value(&self.schema).unwrap();
        let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
            "policy_epoch":epoch,"key_ring":self.signer.key_ring().to_cbor(),"schema_version":1});
        let mut feed = json!({"revision":revision,"policy_epoch":epoch,"key_ring":self.signer.key_ring().to_cbor(),
            "manifest":self.sign(Kind::SettingsSnapshot, manifest)});
        for (name, kind, content) in [
            (
                "settings",
                Kind::SettingsSnapshot,
                json!({"action/admission":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}),
            ),
            ("schema", Kind::SchemaSnapshot, schema.clone()),
            (
                "schema_versions",
                Kind::SchemaSnapshot,
                json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
            ),
            ("communities", Kind::CommunitiesSnapshot, json!(["alpha"])),
            (
                "revocations",
                Kind::RevocationListSnapshot,
                json!({"members":members,"devices":devices}),
            ),
        ] {
            feed[name] = json!(self.sign(kind,json!({"community":"alpha","revision":revision,"policy_epoch":epoch,"content":content})));
        }
        self.charter
            .install(&serde_json::to_vec(&feed).unwrap(), self.now)
            .unwrap();
    }
    pub async fn profile(&mut self, peer: &mut keys::Peer) -> cpfl::Publication {
        let mut draft = cpfl::Draft::new(
            peer.binding.member().into(),
            cshm::Profile {
                community: "alpha".into(),
                schema_version: 1,
                public: [("bio".into(), json!("reading"))].into(),
                private: Default::default(),
            },
        )
        .unwrap();
        let pins = draft
            .prepare_pins(&self.schema, &clean, &mut support::Random::new(29))
            .unwrap();
        let credential = self.sign(
            Kind::Credential,
            json!({
                "purpose":"cplc.community-credential.v2","issuance_action":ACTION,
                "community":"alpha","member":peer.binding.member(),"handle":"mountain",
                "schema_version":1,"policy_epoch":2,"gates":[],"pins":pins,
                "devices":[peer.certificate.device.value()]
            }),
        );
        let current = self.charter.current(NOW).unwrap();
        let policy = current.admission_policy(ACTION, NOW, 300).unwrap();
        let schema = current.publication(cchr::Kind::Schema).signed_bytes();
        let candidate = peer
            .keys
            .with_profile_custody(|mut signer, custody| {
                draft.prepare_publication(
                    &credential,
                    &policy,
                    schema,
                    1,
                    1,
                    vec![1, 2],
                    0,
                    &mut signer,
                    &custody,
                    &cpfl::PortableCodec,
                    &clean,
                    &|_: &str| None,
                )
            })
            .await
            .unwrap()
            .unwrap();
        let cipher = ckmg::passkey::store_cipher(&support::prf(40), "alpha").unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
            .await
            .unwrap();
        candidate
            .commit_publication(
                &mut store,
                cpfl::Validation {
                    policy,
                    signed_schema: schema,
                    contact: &clean,
                },
                [41; 32],
                vec![],
            )
            .await
            .unwrap();
        let committed = cpfl::load_current_committed(
            &store,
            &peer.binding,
            cpfl::Validation {
                policy: current.admission_policy(ACTION, NOW, 300).unwrap(),
                signed_schema: schema,
                contact: &clean,
            },
        )
        .unwrap()
        .unwrap();
        cpfl::Publication::from_bytes(committed.bytes()).unwrap()
    }
}
