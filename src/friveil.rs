use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, PackedField};
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
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
    config::{B1, B128, StdChallenger},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
    pcs::verify,
};
use itertools::Itertools;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::iter::repeat_with;

pub struct FriVeil<P>
where
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
{
    merkle_prover:
        BinaryMerkleTreeProver<P::Scalar, StdDigest, ParallelCompressionAdaptor<StdCompression>>,
    log_inv_rate: usize,
    num_test_queries: usize,
    n_vars: usize,
    log_scalar_bit_width: usize,
}

impl<P> FriVeil<P>
where
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
{
    pub fn new(
        log_inv_rate: usize,
        num_test_queries: usize,
        n_vars: usize,
        log_scalar_bit_width: usize,
    ) -> Self {
        Self {
            merkle_prover: BinaryMerkleTreeProver::<P::Scalar, StdDigest, _>::new(
                ParallelCompressionAdaptor::new(StdCompression::default()),
            ),
            log_inv_rate,
            num_test_queries,
            n_vars,
            log_scalar_bit_width,
        }
    }

    fn get_packed_buffer(&self, values: &[P::Scalar]) -> FieldBuffer<P> {
        FieldBuffer::<P>::from_values(values).unwrap()
    }

    pub fn initialize_fri_context(
        &self,
        values: &[P::Scalar],
    ) -> Result<(FieldBuffer<P>, ReedSolomonCode<B128>, FRIParams<P::Scalar>), String> {
        let packed_buffer = self.get_packed_buffer(values);

        let committed_rs_code =
            ReedSolomonCode::<B128>::new(packed_buffer.log_len(), self.log_inv_rate).unwrap();

        let fri_log_batch_size = 0;

        let fri_arities = if P::LOG_WIDTH == 2 {
            vec![2, 2]
        } else {
            vec![1; packed_buffer.log_len() - 1]
        };

        let fri_params = FRIParams::new(
            committed_rs_code.clone(),
            fri_log_batch_size,
            fri_arities,
            self.num_test_queries,
        )
        .map_err(|e| e.to_string())?;

        Ok((packed_buffer, committed_rs_code, fri_params))
    }

    pub fn calculate_evaluation_context(
        &self,
        values: &[P::Scalar],
    ) -> Result<(Vec<P::Scalar>, P::Scalar), String> {
        let lifted_small_field_mle = self.lift_small_to_large_field::<B1, P::Scalar>(
            &self.large_field_mle_to_small_field_mle::<B1, P::Scalar>(&values),
        );

        let evaluation_point = self.random_scalars::<P::Scalar>(self.n_vars);

        let evaluation_claim = inner_product::<P::Scalar>(
            lifted_small_field_mle,
            eq_ind_partial_eval(&evaluation_point)
                .as_ref()
                .iter()
                .copied()
                .collect_vec(),
        );

        Ok((evaluation_point, evaluation_claim))
    }

    pub fn prove(
        &self,
        message: &[P::Scalar],
        evaluation_point: &[P::Scalar],
    ) -> Result<
        (
            VerifierTranscript<StdChallenger>,
            ReedSolomonCode<P::Scalar>,
            FRIParams<P::Scalar>,
        ),
        String,
    > {
        let (packed_mle, committed_rs_code, fri_params) = self.initialize_fri_context(message)?;
        let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len()).unwrap();
        let domain_context = domain_context::GenericPreExpanded::generate_from_subspace(&subspace);
        let ntt = NeighborsLastSingleThread::new(domain_context);

        let pcs = OneBitPCSProver::new(&ntt, &self.merkle_prover, &fri_params);

        let commit_output = pcs.commit(packed_mle.clone()).unwrap();

        let mut prover_transcript = ProverTranscript::new(StdChallenger::default());

        prover_transcript.message().write(&commit_output.commitment);

        pcs.prove(
            &commit_output.codeword,
            &commit_output.committed,
            packed_mle,
            evaluation_point.to_vec(),
            &mut prover_transcript,
        )
        .map_err(|e| e.to_string())?;

        Ok((
            prover_transcript.into_verifier(),
            committed_rs_code,
            fri_params,
        ))
    }

    pub fn verify_and_open(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        evaluation_claim: P::Scalar,
        evaluation_point: &[P::Scalar],
        fri_params: &FRIParams<P::Scalar>,
    ) -> Result<(), String> {
        let retrieved_codeword_commitment = verifier_transcript
            .message()
            .read()
            .map_err(|e| e.to_string())?;

        let merkle_prover_scheme = self.merkle_prover.scheme().clone();
        verify(
            verifier_transcript,
            evaluation_claim,
            evaluation_point,
            retrieved_codeword_commitment,
            fri_params,
            &merkle_prover_scheme,
        )
        .map_err(|e| e.to_string())
    }

    pub fn lift_small_to_large_field<F, FE>(&self, small_field_elms: &[F]) -> Vec<FE>
    where
        F: Field,
        FE: Field + ExtensionField<F>,
    {
        small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
    }

    fn large_field_mle_to_small_field_mle<F, FE>(&self, large_field_mle: &[FE]) -> Vec<F>
    where
        F: Field,
        FE: Field + ExtensionField<F>,
    {
        large_field_mle
            .iter()
            .flat_map(|elm| ExtensionField::<F>::iter_bases(elm))
            .collect()
    }

    pub fn random_scalars<F: Field>(&self, n: usize) -> Vec<F> {
        let mut rng = StdRng::from_seed([0; 32]);
        repeat_with(|| F::random(&mut rng)).take(n).collect()
    }
}
