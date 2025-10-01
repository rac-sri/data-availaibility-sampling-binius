use binius_field::{ExtensionField, Field, PackedField};
use binius_math::{
    BinarySubspace, FieldBuffer, ReedSolomonCode,
    inner_product::inner_product,
    multilinear::eq::eq_ind_partial_eval,
    ntt::{
        NeighborsLastSingleThread,
        domain_context::{self, GenericPreExpanded},
    },
};
use binius_prover::{
    hash::parallel_compression::ParallelCompressionAdaptor,
    merkle_tree::prover::BinaryMerkleTreeProver, pcs::OneBitPCSProver,
};
use binius_transcript::ProverTranscript;
use binius_verifier::{
    config::{B1, B128, StdChallenger},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
    merkle_tree::BinaryMerkleTreeScheme,
    pcs::verify,
};
use itertools::Itertools;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::iter::repeat_with;

use crate::friveil::FriVeil;

mod friveil;

fn main() {
    //this should be the base-2 logarithm of the number of cores.
    const LOG_SIZE_CORES: usize = 3;
    const LOG_INV_RATE: usize = 1;
    const NUM_TEST_QUERIES: usize = 3;

    type P = B128;

    let n_vars = 12;
    let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
    let big_field_n_vars = n_vars - log_scalar_bit_width;

    let mut rng = StdRng::from_seed([0; 32]);

    let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);

    let friveil = FriVeil::<
        B128,
        BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
        NeighborsLastSingleThread<GenericPreExpanded<B128>>,
    >::new(LOG_INV_RATE, NUM_TEST_QUERIES, n_vars);
    let (evaluation_point, evaluation_claim) = friveil
        .calculate_evaluation_context(&packed_mle_values)
        .unwrap();
    let (packed_mle, fri_params, ntt) = friveil.initialize_fri_context(&packed_mle_values).unwrap();

    let commit_output = friveil
        .commit(packed_mle.clone(), fri_params.clone(), &ntt)
        .unwrap();

    let (mut verifier_transcript, fri_params) = friveil
        .prove(
            packed_mle,
            fri_params,
            &ntt,
            &commit_output,
            &evaluation_point,
        )
        .unwrap();

    let result = friveil.verify_and_open(
        &mut verifier_transcript,
        evaluation_claim,
        &evaluation_point,
        &fri_params,
    );

    println!("result: {:?}", result);
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
