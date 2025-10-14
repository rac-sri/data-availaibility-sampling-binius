use binius_field::{ExtensionField, Field};
use binius_math::ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded};
use binius_verifier::{
    config::{B1, B128},
    hash::{StdCompression, StdDigest},
    merkle_tree::BinaryMerkleTreeScheme,
};
use rand::RngCore;
use std::iter::repeat_with;

use crate::{friveil::FriVeil, poly::bytes_to_packed_mle};

mod poly;

mod friveil;

fn main() {
    //this should be the base-2 logarithm of the number of cores.

    use std::time::Instant;

    const LOG_INV_RATE: usize = 1;
    const NUM_TEST_QUERIES: usize = 3;

    let random_data_bytes = [0u8; 32 * 1024]; // 32 KB of zero bytes

    let (packed_mle_values, packed_mle_values_vec, n_vars) =
        bytes_to_packed_mle::<B128>(&random_data_bytes).unwrap();

    let start = Instant::now();
    let friveil = FriVeil::<
        B128,
        BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
        NeighborsLastMultiThread<GenericPreExpanded<B128>>,
    >::new(LOG_INV_RATE, NUM_TEST_QUERIES, n_vars, 3);
    println!("friveil initialized ({} ms)", start.elapsed().as_millis());

    let start = Instant::now();
    let evaluation_point = friveil.calculate_evaluation_point_with_position(3).unwrap();

    println!("evaluation point len - {:?}", evaluation_point.len());
    println!(
        "evaluation context calculated ({} ms)",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    let (packed_mle, fri_params, ntt) = friveil.initialize_fri_context(packed_mle_values).unwrap();
    println!(
        "fri context initialized ({} ms)",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    let commit_output = friveil
        .commit(packed_mle.clone(), fri_params.clone(), &ntt)
        .unwrap();
    println!(
        "commit output generated ({} ms) of size {}",
        start.elapsed().as_millis(),
        commit_output.commitment.len(),
    );

    let start = Instant::now();
    let (mut verifier_transcript) = friveil
        .prove(
            packed_mle,
            fri_params.clone(),
            &ntt,
            &commit_output,
            &evaluation_point,
        )
        .unwrap();
    println!("proof generated ({} ms)", start.elapsed().as_millis());

    let start = Instant::now();
    let evaluation_claim = friveil
        .calculate_evaluation_claim(&packed_mle_values_vec, &evaluation_point)
        .unwrap();
    println!(
        "evaluation claim generated ({} ms)",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    let result = friveil.verify_and_open(
        &mut verifier_transcript,
        evaluation_claim,
        &evaluation_point,
        &fri_params,
    );
    println!(
        "verification and opening complete ({} ms)",
        start.elapsed().as_millis()
    );

    let start = Instant::now();
    println!("result: {:?}", result);
    println!(
        "result logging complete ({} ms)",
        start.elapsed().as_millis()
    );
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
