use crate::{friveil::FriVeil, poly::FriVeilUtils};
use binius_field::{ExtensionField, Field};
use binius_math::ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded};
use binius_prover::merkle_tree::MerkleTreeProver;
use binius_transcript::{ProverTranscript, TranscriptWriter};
use binius_verifier::{
    config::{B1, B128, StdChallenger},
    hash::{StdCompression, StdDigest},
    merkle_tree::{BinaryMerkleTreeScheme, MerkleTreeScheme},
};
use core::slice;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::iter::repeat_with;
use std::time::Instant;
use tracing::{debug, error, info, warn};

mod friveil;
mod poly;

fn main() {
    //this should be the base-2 logarithm of the number of cores.

    tracing_subscriber::fmt::init();

    const LOG_INV_RATE: usize = 1;
    const NUM_TEST_QUERIES: usize = 3;

    // Create arbitrary (nonzero, patterned) data instead of all zeroes.
    info!("Generating random patterned input data...");
    let random_data_bytes: Vec<u8> = (0..14 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    let start = Instant::now();
    info!("Converting input bytes to packed MLE...");
    let packed_mle_values = FriVeilUtils::<B128>::new()
        .bytes_to_packed_mle(&random_data_bytes)
        .unwrap();

    info!(
        "Packed MLE values: {:?}",
        packed_mle_values.packed_values.get(0..2)
    );
    info!(
        "Packed MLE values generated in {} ms (n_vars = {})",
        start.elapsed().as_millis(),
        packed_mle_values.total_n_vars
    );
    info!(
        "Packed MLE values: {:?}",
        packed_mle_values.packed_values.len()
    );

    let start = Instant::now();
    info!("Initializing FRIVeil context...");
    let friveil = FriVeil::<
        B128,
        BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
        NeighborsLastMultiThread<GenericPreExpanded<B128>>,
    >::new(
        LOG_INV_RATE,
        NUM_TEST_QUERIES,
        packed_mle_values.total_n_vars,
        3,
    );
    info!("FRIVeil initialized in {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    info!("Calculating evaluation point at position 3...");

    let evaluation_point = friveil.calculate_evaluation_point_random().unwrap();

    info!("Evaluation point length: {}", evaluation_point.len());
    info!(
        "Evaluation context calculated in {} ms",
        start.elapsed().as_millis()
    );

    let (fri_params, ntt) = friveil
        .initialize_fri_context(packed_mle_values.packed_mle.clone())
        .unwrap();

    let start = Instant::now();
    info!("Committing to MLE...");
    let commit_output = friveil
        .commit(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
        )
        .unwrap();

    // SAMPLING
    for (i, value) in commit_output.codeword.iter().enumerate() {
        let mut inclusion_proof = friveil
            .inclusion_proof(&commit_output.committed, i)
            .unwrap();

        let result = friveil
            .verify_inclusion_proof(
                &mut inclusion_proof,
                &[*value],
                i,
                &fri_params,
                &commit_output.committed,
            )
            .unwrap();
        info!("Sampling point: {} with value: {:?} success", i, value);
    }
    info!(
        "Commit output generated in {} ms (commitment size: {})",
        start.elapsed().as_millis(),
        commit_output.commitment.len(),
    );

    let start = Instant::now();
    info!("Generating proof...");
    let (mut verifier_transcript) = friveil
        .prove(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
            &commit_output,
            &evaluation_point,
        )
        .unwrap();
    info!("Proof generated in {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    info!("Calculating evaluation claim...");
    let evaluation_claim = friveil
        .calculate_evaluation_claim(&packed_mle_values.packed_values, &evaluation_point)
        .unwrap();
    debug!("Evaluation claim: {:?}", evaluation_claim);
    info!(
        "Evaluation claim generated in {} ms",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    info!("Running verification and opening...");
    let result = friveil.verify_evaluation(
        &mut verifier_transcript,
        evaluation_claim,
        &evaluation_point,
        &fri_params,
    );
    match &result {
        Ok(_) => info!("Verification succeeded."),
        Err(e) => error!("Verification failed: {:?}", e),
    }
    info!(
        "Verification and opening complete in {} ms",
        start.elapsed().as_millis()
    );

    info!("Final result: {:?}", result);
}

pub fn random_scalars<F: Field>(mut rng: impl RngCore, n: usize) -> Vec<F> {
    repeat_with(|| F::random(&mut rng)).take(n).collect()
}

pub fn lift_small_to_large_field<F, FE>(small_field_elms: &[F]) -> Vec<FE>
where
    F: Field,
    FE: Field + ExtensionField<F>,
{
    small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
}

pub fn large_field_mle_to_small_field_mle<F, FE>(large_field_mle: &[FE]) -> Vec<F>
where
    F: Field,
    FE: Field + ExtensionField<F>,
{
    large_field_mle
        .iter()
        .flat_map(|elm| ExtensionField::<F>::iter_bases(elm))
        .collect()
}
