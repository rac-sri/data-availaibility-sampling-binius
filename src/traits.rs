use binius_field::PackedExtension;
pub use binius_field::PackedField;
use binius_math::ntt::{AdditiveNTT, NeighborsLastMultiThread, domain_context::GenericPreExpanded};
use binius_prover::{
    hash::parallel_compression::ParallelCompressionAdaptor,
    merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver},
};
use binius_transcript::VerifierTranscript;
pub use binius_verifier::config::B128;
use binius_verifier::{
    config::{B1, StdChallenger},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
};
use std::mem::MaybeUninit;

pub trait FRIVeilSampling<
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
    NTT: AdditiveNTT<Field = B128> + Sync,
>
{
    fn reconstruct_codeword_naive(
        &self,
        corrupted_codeword: &mut [P::Scalar],
        corrupted_indices: &[usize],
    ) -> Result<(), String>;
    fn verify_evaluation(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        evaluation_claim: P::Scalar,
        evaluation_point: &[P::Scalar],
        fri_params: &FRIParams<P::Scalar>,
    ) -> Result<(), String>;

    fn verify_inclusion_proof(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        data: &[P::Scalar],
        index: usize,
        fri_params: &FRIParams<P::Scalar>,
        commitment: [u8; 32],
    ) -> Result<(), String>;

    fn inclusion_proof(
        &self,
        committed: &<BinaryMerkleTreeProver<
            P::Scalar,
            StdDigest,
            ParallelCompressionAdaptor<StdCompression>,
        > as MerkleTreeProver<P::Scalar>>::Committed,
        index: usize,
    ) -> Result<VerifierTranscript<StdChallenger>, String>;

    fn decode_codeword(
        &self,
        codeword: &[P::Scalar],
        fri_params: FRIParams<P::Scalar>,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
    ) -> Result<Vec<P::Scalar>, String>;

    fn extract_commitment(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
    ) -> Result<Vec<u8>, String>;

    fn decode_batch(
        &self,
        log_dim: usize,
        log_inv: usize,
        log_batch_size: usize,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
        data: &[P::Scalar],
        output: &mut [MaybeUninit<P::Scalar>],
    ) -> Result<(), String>;
}

pub trait FriVeilUtils {
    fn get_transcript_bytes(&self, transcript: &VerifierTranscript<StdChallenger>) -> Vec<u8>;
    fn reconstruct_transcript_from_bytes(
        &self,
        bytes: Vec<u8>,
    ) -> VerifierTranscript<StdChallenger>;
}
