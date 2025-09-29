use std::iter::repeat_with;

use binius_field::{BinaryField128bGhash, ExtensionField, Field};
use binius_math::{
    FieldBuffer, ReedSolomonCode,
    ntt::{NeighborsLastMultiThread as NTT, domain_context},
};
use binius_prover::{
    hash::parallel_compression::ParallelCompressionAdaptor,
    merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver},
    pcs::OneBitPCSProver,
};
use binius_verifier::{
    config::{B1, B128},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
};
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn main() {
    println!("Hello, world!");

    //this should be the base-2 logarithm of the number of cores.
    const LOG_SIZE_CORES: usize = 3;
    const LOG_SIZE: usize = 6;
    const LOG_INV_RATE: usize = 1;
    const NUM_TEST_QUERIES: usize = 3;

    type F = binius_field::BinaryField128bGhash;

    let n_vars = 12;
    let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
    let big_field_n_vars = n_vars - log_scalar_bit_width;

    let mut rng = StdRng::from_seed([0; 32]);

    let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);

    let lifted_small_field_mle: Vec<B128> = lift_small_to_large_field(
        &large_field_mle_to_small_field_mle::<B1, B128>(&packed_mle_values),
    );

    let packed_mle = FieldBuffer::<BinaryField128bGhash>::from_values(&packed_mle_values)
        .expect("failed to create field buffer");

    let domain_context = domain_context::GaoMateerPreExpanded::<F>::generate(LOG_SIZE);
    let ntt = NTT::new(domain_context, LOG_SIZE_CORES);
    let merkle_prover = BinaryMerkleTreeProver::<B128, StdDigest, _>::new(
        ParallelCompressionAdaptor::new(StdCompression::default()),
    );

    let committed_rs_code =
        ReedSolomonCode::<B128>::new(packed_mle.log_len(), LOG_INV_RATE).unwrap();

    let fri_log_batch_size = 0;

    // fri arities must support the packing width of the mle
    // let fri_arities = if P::LOG_WIDTH == 2 {
    //     vec![2, 2]
    // } else {
    //     vec![1; packed_mle.log_len() - 1]
    // };

    let fri_arities = vec![2, 2];

    let fri_params = FRIParams::new(
        committed_rs_code,
        fri_log_batch_size,
        fri_arities,
        NUM_TEST_QUERIES,
    )
    .unwrap();
    let pcs = OneBitPCSProver::new(&ntt, &merkle_prover, &fri_params);
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
