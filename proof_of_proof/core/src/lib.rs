use FRIVeil::friveil::B128;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    pub data_flat: Vec<u8>,
    pub proof_lengths: Vec<usize>,
    pub evaluation_point: Vec<[u8; 16]>,
    pub evaluation_claim: [u8; 16],
    pub packed_values_log_len: usize,
}

impl GuestInput {
    /// Get a specific proof by index without allocation
    /// Returns a slice into the flat buffer
    pub fn get_proof(&self, index: usize) -> &[u8] {
        let start: usize = self.proof_lengths[..index].iter().sum();
        let end = start + self.proof_lengths[index];
        &self.data_flat[start..end]
    }

    /// Get number of proofs
    pub fn num_proofs(&self) -> usize {
        self.proof_lengths.len()
    }

    /// Create GuestInput from individual proof bytes
    /// Helper for host-side construction
    pub fn from_proofs(
        proofs: Vec<Vec<u8>>,
        evaluation_point: Vec<B128>,
        evaluation_claim: B128,
        packed_values_log_len: usize,
    ) -> Self {
        let proof_lengths: Vec<usize> = proofs.iter().map(|p| p.len()).collect();
        let data_flat: Vec<u8> = proofs.into_iter().flatten().collect();
        let evaluation_point: Vec<[u8; 16]> = evaluation_point
            .into_iter()
            .map(|b128| b128.val().to_le_bytes())
            .collect();
        let evaluation_claim: [u8; 16] = evaluation_claim.val().to_le_bytes();

        Self {
            data_flat,
            proof_lengths,
            evaluation_point,
            evaluation_claim,
            packed_values_log_len,
        }
    }
}
