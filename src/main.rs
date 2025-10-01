use binius_field::{ExtensionField, Field, PackedField};
use binius_math::{
    BinarySubspace, FieldBuffer, ReedSolomonCode,
    inner_product::inner_product,
    multilinear::eq::eq_ind_partial_eval,
    ntt::{NeighborsLastSingleThread, domain_context},
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

    let friveil =
        FriVeil::<B128>::new(LOG_INV_RATE, NUM_TEST_QUERIES, n_vars, log_scalar_bit_width);
    let (evaluation_point, evaluation_claim) = friveil
        .calculate_evaluation_context(&packed_mle_values)
        .unwrap();
    let (mut verifier_transcript, committed_rs_code, fri_params) = friveil
        .prove(&packed_mle_values, &evaluation_point)
        .unwrap();

    let result = friveil.verify_and_open(
        &mut verifier_transcript,
        evaluation_claim,
        &evaluation_point,
        &fri_params,
    );

    println!("result: {:?}", result);

    // let lifted_small_field_mle = lift_small_to_large_field(&large_field_mle_to_small_field_mle::<
    //     B1,
    //     B128,
    // >(&packed_mle_values));

    // let evaluation_point = random_scalars::<B128>(&mut rng, n_vars);
    // assert!(1 << evaluation_point.len() == lifted_small_field_mle.len());
    // let evaluation_claim = inner_product::<B128>(
    //     lifted_small_field_mle,
    //     eq_ind_partial_eval(&evaluation_point)
    //         .as_ref()
    //         .iter()
    //         .copied()
    //         .collect_vec(),
    // );

    // let merkle_prover = BinaryMerkleTreeProver::<B128, StdDigest, _>::new(
    //     ParallelCompressionAdaptor::new(StdCompression::default()),
    // );

    // let committed_rs_code =
    //     ReedSolomonCode::<B128>::new(packed_mle.log_len(), LOG_INV_RATE).unwrap();

    // let fri_log_batch_size = 0;

    // // fri arities must support the packing width of the mle
    // let fri_arities = if P::LOG_WIDTH == 2 {
    //     vec![2, 2]
    // } else {
    //     vec![1; packed_mle.log_len() - 1]
    // };

    // let fri_params = FRIParams::new(
    //     committed_rs_code,
    //     fri_log_batch_size,
    //     fri_arities,
    //     NUM_TEST_QUERIES,
    // )
    // .unwrap();

    // let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len()).unwrap();
    // let domain_context = domain_context::GenericPreExpanded::generate_from_subspace(&subspace);
    // let ntt = NeighborsLastSingleThread::new(domain_context);

    // let pcs = OneBitPCSProver::new(&ntt, &merkle_prover, &fri_params);

    // let commit_output = pcs.commit(packed_mle.clone()).unwrap();

    // let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
    // prover_transcript.message().write(&commit_output.commitment);

    // let i = pcs.prove(
    //     &commit_output.codeword,
    //     &commit_output.committed,
    //     packed_mle,
    //     evaluation_point.clone(),
    //     &mut prover_transcript,
    // );

    // println!("i: {:?}", i);

    // let mut verifier_transcript = prover_transcript.into_verifier();

    // let retrieved_codeword_commitment = verifier_transcript.message().read().unwrap();

    // let result = verify(
    //     &mut verifier_transcript,
    //     evaluation_claim,
    //     &evaluation_point,
    //     retrieved_codeword_commitment,
    //     &fri_params,
    //     merkle_prover.scheme(),
    // );

    // println!("result: {:?}", result);
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
