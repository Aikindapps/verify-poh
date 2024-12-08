use std::collections::HashMap;
use candid::Principal;
use ic_cdk_macros::query;
use ic_verifiable_credentials::issuer_api::CredentialSpec;
use ic_verifiable_credentials::VcFlowSigners;

pub type CanisterId = Principal;
pub type TimestampMillis = u64;

use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct UniquePersonProof {
    pub timestamp: TimestampMillis,
    pub provider: UniquePersonProofProvider,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum UniquePersonProofProvider {
    DecideAI,
}

const ISSUER_CANISTER_ID: CanisterId = CanisterId::from_slice(&[0, 0, 0, 0, 0, 240, 24, 173, 1, 1]);
const ISSUER_ORIGIN: &str = "https://id.decideai.xyz/";
const II_CANISTER_ID: CanisterId = CanisterId::from_slice(&[0, 0, 0, 0, 0, 0, 0, 7, 1, 1]);
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const IC_ROOT_KEY: [u8; 133] = [48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 129, 76, 14, 110, 199, 31, 171, 88, 59, 8, 189, 129, 55, 60, 37, 92, 60, 55, 27, 46, 132, 134, 60, 152, 164, 241, 224, 139, 116, 35, 93, 20, 251, 93, 156, 12, 213, 70, 217, 104, 95, 145, 58, 12, 11, 44, 197, 52, 21, 131, 191, 75, 67, 146, 228, 103, 219, 150, 214, 91, 155, 180, 203, 113, 113, 18, 248, 71, 46, 13, 90, 77, 20, 80, 95, 253, 116, 132, 176, 18, 145, 9, 28, 95, 135, 185, 136, 131, 70, 63, 152, 9, 26, 11, 170, 174];
//const fetched_root_key: Vec<u8> = read_root_key(&self);

#[query]
pub fn verify_proof_of_unique_personhood(
    principal: Principal,
    credential_jwt: String,
    effective_derivation_origin: String,
    now: TimestampMillis,
) -> Result<UniquePersonProof, String> {
    let root_pk_raw = &IC_ROOT_KEY[IC_ROOT_KEY.len().saturating_sub(96)..];

    let mut argument = HashMap::new();
    argument.insert(
        "minimumVerificationDate".to_string(),
        ic_verifiable_credentials::issuer_api::ArgumentValue::String("2020-12-01T00:00:00Z".to_string()),
    );

    match ic_verifiable_credentials::validate_ii_presentation_and_claims(
        &credential_jwt,
        principal,
        effective_derivation_origin,
        &VcFlowSigners {
            ii_canister_id: II_CANISTER_ID,
            ii_origin: "https://identity.ic0.app/".to_string(),
            issuer_canister_id: ISSUER_CANISTER_ID,
            issuer_origin: ISSUER_ORIGIN.to_string(),
        },
        &CredentialSpec {
            credential_type: "ProofOfUniqueness".to_string(),
            arguments: Some(argument),
        },
        root_pk_raw,
        (now * NANOS_PER_MILLISECOND) as u128,
    ) {
        Ok(_) => Ok(UniquePersonProof {
            timestamp: now,
            provider: UniquePersonProofProvider::DecideAI,
        }),
        Err(error) => Err(format!("{error:?}")),
    }
}

#[test]
fn signing_canister_id() {
    assert_eq!(
        ISSUER_CANISTER_ID,
        CanisterId::from_text("qgxyr-pyaaa-aaaah-qdcwq-cai").unwrap()
    );
}

ic_cdk::export_candid!();
