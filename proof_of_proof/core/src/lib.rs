use FRIVeil::friveil::B128;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    pub data: Vec<Vec<u8>>,
    pub evaluation_point: Vec<[u8; 16]>,
    pub evaluation_claim: [u8; 16],
    pub packed_values_log_len: usize,
}

pub type GuestInputTuple = (Vec<Vec<u8>>, Vec<[u8; 16]>, [u8; 16], usize);

impl GuestInput {
    /// Create GuestInput from individual proof bytes
    /// Helper for host-side construction
    pub fn from_proofs(
        proofs: Vec<Vec<u8>>,
        evaluation_point: Vec<B128>,
        evaluation_claim: B128,
        packed_values_log_len: usize,
    ) -> Self {
        let evaluation_point: Vec<[u8; 16]> = evaluation_point
            .into_iter()
            .map(|b128| b128.val().to_le_bytes())
            .collect();
        let evaluation_claim: [u8; 16] = evaluation_claim.val().to_le_bytes();

        Self {
            data: proofs,
            evaluation_point,
            evaluation_claim,
            packed_values_log_len,
        }
    }

    pub fn to_tuple(&self) -> GuestInputTuple {
        (
            self.data.clone(),
            self.evaluation_point.clone(),
            self.evaluation_claim,
            self.packed_values_log_len,
        )
    }
}
