use crate::{friveil::FriVeil, poly::FriVeilUtils};
use binius_field::{ExtensionField, Field};
use binius_math::ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded};
use binius_verifier::{
    config::{B1, B128},
    hash::{StdCompression, StdDigest},
    merkle_tree::BinaryMerkleTreeScheme,
};
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
    let random_data_bytes: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

    let start = Instant::now();
    info!("Converting input bytes to packed MLE...");
    let (packed_mle_values, packed_mle_values_vec, n_vars) = FriVeilUtils::<B128>::new()
        .bytes_to_packed_mle(&random_data_bytes)
        .unwrap();

    info!("Packed MLE values: {:?}", packed_mle_values_vec.get(0..2));
    info!(
        "Packed MLE values generated in {} ms (n_vars = {})",
        start.elapsed().as_millis(),
        n_vars
    );
    info!("Packed MLE values: {:?}", packed_mle_values_vec.len());

    let start = Instant::now();
    info!("Initializing FRIVeil context...");
    let friveil = FriVeil::<
        B128,
        BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
        NeighborsLastMultiThread<GenericPreExpanded<B128>>,
    >::new(LOG_INV_RATE, NUM_TEST_QUERIES, n_vars, 3);
    info!("FRIVeil initialized in {} ms", start.elapsed().as_millis());

    let start = Instant::now();
    info!("Calculating evaluation point at position 3...");
    let evaluation_point = friveil.calculate_evaluation_point_with_position(3).unwrap();

    info!("Evaluation point length: {}", evaluation_point.len());
    info!(
        "Evaluation context calculated in {} ms",
        start.elapsed().as_millis()
    );

    let (packed_mle, fri_params, ntt) = friveil.initialize_fri_context(packed_mle_values).unwrap();

    let start = Instant::now();
    info!("Committing to MLE...");
    let commit_output = friveil
        .commit(packed_mle.clone(), fri_params.clone(), &ntt)
        .unwrap();
    info!(
        "Commit output generated in {} ms (commitment size: {})",
        start.elapsed().as_millis(),
        commit_output.commitment.len(),
    );

    let start = Instant::now();
    info!("Generating proof...");
    let (mut verifier_transcript) = friveil
        .prove(
            packed_mle,
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
        .calculate_evaluation_claim(&packed_mle_values_vec, &evaluation_point)
        .unwrap();
    debug!("Evaluation claim: {:?}", evaluation_claim);
    info!(
        "Evaluation claim generated in {} ms",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    info!("Running verification and opening...");
    let result = friveil.verify_and_open(
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

// multi thread log inv = 3
// packed mle values generated (1905 ms)
// friveil initialized (0 ms)
// evaluation context calculated (0 ms)
// fri context initialized (277 ms)
// commit output generated (7831 ms)
// proof generated (7750 ms)
// evaluation claim generated (154951 ms)
// verification and opening complete (8 ms)
// result: Ok(())
// result logging complete (0 ms)

// single thread
// packed mle values generated (1911 ms)
// friveil initialized (0 ms)
// evaluation context calculated (0 ms)
// fri context initialized (278 ms)
// commit output generated (26202 ms)
// proof generated (8064 ms)
// evaluation claim generated (152558 ms)
// verification and opening complete (8 ms)
// result: Ok(())
// result logging complete (0 ms)
