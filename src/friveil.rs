use binius_field::{ExtensionField, Field, PackedExtension, PackedField, Random};
use binius_math::{
    BinarySubspace, FieldBuffer, ReedSolomonCode,
    inner_product::inner_product,
    multilinear::eq::eq_ind_partial_eval,
    ntt::{
        AdditiveNTT, NeighborsLastMultiThread,
        domain_context::{self, GenericPreExpanded},
    },
};
use binius_prover::{
    fri::CommitOutput,
    hash::parallel_compression::ParallelCompressionAdaptor,
    merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver},
    pcs::OneBitPCSProver,
};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
    config::{B1, B128, StdChallenger},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
    merkle_tree::{BinaryMerkleTreeScheme, MerkleTreeScheme},
    pcs::verify,
};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};
use std::{iter::repeat_with, marker::PhantomData};

pub type FriVeilDefault = FriVeil<
    'static,
    B128,
    BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
    NeighborsLastMultiThread<GenericPreExpanded<B128>>,
>;
pub struct FriVeil<'a, P, VCS, NTT>
where
    NTT: AdditiveNTT<Field = B128> + Sync,
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
    VCS: MerkleTreeScheme<P::Scalar>,
{
    _ntt: PhantomData<&'a NTT>,
    pub merkle_prover:
        BinaryMerkleTreeProver<P::Scalar, StdDigest, ParallelCompressionAdaptor<StdCompression>>,
    log_inv_rate: usize,
    num_test_queries: usize,
    n_vars: usize,
    log_num_shares: usize,

    _vcs: PhantomData<VCS>,
}

impl<'a, P, VCS, NTT> FriVeil<'a, P, VCS, NTT>
where
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
    VCS: MerkleTreeScheme<P::Scalar>,
    NTT: AdditiveNTT<Field = B128> + Sync,
{
    pub fn new(
        log_inv_rate: usize,
        num_test_queries: usize,
        n_vars: usize,
        log_num_shares: usize,
    ) -> Self {
        Self {
            merkle_prover: BinaryMerkleTreeProver::<P::Scalar, StdDigest, _>::new(
                ParallelCompressionAdaptor::new(StdCompression::default()),
            ),
            log_inv_rate,
            num_test_queries,
            n_vars,
            log_num_shares,
            _ntt: PhantomData,
            _vcs: PhantomData,
        }
    }

    pub fn initialize_fri_context(
        &self,
        packed_buffer: FieldBuffer<P>,
    ) -> Result<
        (
            FRIParams<P::Scalar>,
            NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
        ),
        String,
    > {
        let committed_rs_code =
            ReedSolomonCode::<B128>::new(packed_buffer.log_len(), self.log_inv_rate).unwrap();

        let fri_log_batch_size = 0;

        let fri_arities = if P::LOG_WIDTH == 2 {
            vec![2, 2]
        } else {
            vec![2; packed_buffer.log_len()/2]
        };

        let fri_params = FRIParams::new(
            committed_rs_code.clone(),
            fri_log_batch_size,
            fri_arities,
            self.num_test_queries,
        )
        .map_err(|e| e.to_string())?;

        let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len()).unwrap();

        let domain_context = domain_context::GenericPreExpanded::generate_from_subspace(&subspace);
        let ntt = NeighborsLastMultiThread::new(domain_context, self.log_num_shares);

        Ok((fri_params, ntt))
    }

    pub fn calculate_evaluation_point_random(&self) -> Result<Vec<P::Scalar>, String> {
        let mut rng = StdRng::from_seed([0; 32]);
        let evaluation_point: Vec<P::Scalar> = repeat_with(|| P::Scalar::random(&mut rng))
            .take(self.n_vars)
            .collect();
        Ok(evaluation_point)
    }

    // TODO: optimise
    pub fn calculate_evaluation_claim(
        &self,
        values: &[P::Scalar],
        evaluation_point: &[P::Scalar],
    ) -> Result<P::Scalar, String> {
        let lifted_small_field_mle = self.lift_small_to_large_field::<B1, P::Scalar>(
            &self.large_field_mle_to_small_field_mle::<B1, P::Scalar>(values),
        );

        let evaluation_claim = inner_product::<P::Scalar>(
            lifted_small_field_mle,
            eq_ind_partial_eval(evaluation_point)
                .as_ref()
                .iter()
                .copied()
                .collect_vec(),
        );

        Ok(evaluation_claim)
    }

    pub fn commit(
        &self,
        packed_mle: FieldBuffer<P>,
        fri_params: FRIParams<P::Scalar>,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
    ) -> Result<
        CommitOutput<
            P,
            Vec<u8>,
            <BinaryMerkleTreeProver<
                P::Scalar,
                StdDigest,
                ParallelCompressionAdaptor<StdCompression>,
            > as MerkleTreeProver<P::Scalar>>::Committed,
        >,
        String,
    > {
        let pcs = OneBitPCSProver::new(ntt, &self.merkle_prover, &fri_params);
        let commit_output = pcs.commit(packed_mle.clone()).map_err(|e| e.to_string())?;

        // Convert the digest type
        Ok(CommitOutput {
            codeword: commit_output.codeword,
            commitment: commit_output.commitment.to_vec(),
            committed: commit_output.committed,
        })
    }

    pub fn prove(
        &self,
        packed_mle: FieldBuffer<P>,
        fri_params: FRIParams<P::Scalar>,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
        commit_output: &CommitOutput<
            P,
            Vec<u8>,
            <BinaryMerkleTreeProver<
                P::Scalar,
                StdDigest,
                ParallelCompressionAdaptor<StdCompression>,
            > as MerkleTreeProver<P::Scalar>>::Committed,
        >,
        evaluation_point: &[P::Scalar],
    ) -> Result<VerifierTranscript<StdChallenger>, String> {
        let pcs = OneBitPCSProver::new(ntt, &self.merkle_prover, &fri_params);

        let mut prover_transcript = ProverTranscript::new(StdChallenger::default());

        prover_transcript
            .message()
            .write_bytes(&commit_output.commitment);

        pcs.prove(
            &commit_output.codeword,
            &commit_output.committed,
            packed_mle,
            evaluation_point.to_vec(),
            &mut prover_transcript,
        )
        .map_err(|e| e.to_string())?;

        Ok(prover_transcript.into_verifier())
    }

    pub fn verify_evaluation(
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

    pub fn inclusion_proof(
        &self,
        committed: &<BinaryMerkleTreeProver<
            P::Scalar,
            StdDigest,
            ParallelCompressionAdaptor<StdCompression>,
        > as MerkleTreeProver<P::Scalar>>::Committed,
        index: usize,
    ) -> Result<VerifierTranscript<StdChallenger>, String> {
        let mut proof_writer = ProverTranscript::new(StdChallenger::default());
        self.merkle_prover
            .prove_opening(committed, 0, index, &mut proof_writer.message())
            .map_err(|e| e.to_string())?;

        let proof_reader = proof_writer.into_verifier();

        Ok(proof_reader)
    }

    pub fn verify_inclusion_proof(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        data: &[P::Scalar],
        index: usize,
        fri_params: &FRIParams<P::Scalar>,
        committment: [u8; 32],
    ) -> Result<(), String> {
        let tree_depth = fri_params.rs_code().log_len();
        self.merkle_prover
            .scheme()
            .verify_opening(
                index,
                data,
                0,
                tree_depth,
                &[committment.into()],
                &mut verifier_transcript.message(),
            )
            .map_err(|e| e.to_string())
    }

    // TODO: fix
    // Helper function only, only needed if we wanna observer NTT encoding behaviour outside the `commit` function
    #[allow(dead_code)]
    pub fn encode_codeword(
        &self,
        data: &[P::Scalar],
        fri_params: FRIParams<P::Scalar>,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
    ) -> Result<Vec<P::Scalar>, String> {
        let rs_code = fri_params.rs_code();
        let len = 1
            << (rs_code.log_len() + fri_params.log_batch_size() - P::LOG_WIDTH
                + rs_code.log_inv_rate());
        let mut encoded = Vec::with_capacity(len);
        rs_code
            .encode_batch(
                ntt,
                data.as_ref(),
                encoded.spare_capacity_mut(),
                fri_params.log_batch_size(),
            )
            .map_err(|e| e.to_string())?;
        unsafe {
            // Safety: encode_ext_batch guarantees all elements are initialized on success
            encoded.set_len(len);
        }
        Ok(encoded)
    }

    // pub fn decode_codeword(
    //     &self,
    //     codeword: &[P::Scalar],
    //     fri_params: FRIParams<P::Scalar>,
    //     ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
    // ) -> Result<(), String> {
    //     let mut code_buffer =
    //         FieldBuffer::<P>::from_values(codeword.to_vec().as_ref()).map_err(|e| e.to_string())?;

    //     ntt.inverse_transform(code_buffer.to_mut(), 0, fri_params.log_batch_size());
    //     println!("code_buffer: {:?}", code_buffer.to_ref());
    //     Ok(())
    // }

    #[allow(dead_code)]
    pub fn extract_commitment(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
    ) -> Result<Vec<u8>, String> {
        verifier_transcript
            .message()
            .read()
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
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::poly::FriVeilUtils;
    use binius_field::Field;
    use binius_math::ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded};
    use binius_verifier::{
        config::{B1, B128},
        hash::{StdCompression, StdDigest},
        merkle_tree::BinaryMerkleTreeScheme,
    };

    type TestFriVeil = FriVeil<
        'static,
        B128,
        BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
        NeighborsLastMultiThread<GenericPreExpanded<B128>>,
    >;

    fn create_test_data(size_bytes: usize) -> Vec<u8> {
        (0..size_bytes).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_friveil_new() {
        const LOG_INV_RATE: usize = 1;
        const NUM_TEST_QUERIES: usize = 3;
        const N_VARS: usize = 10;
        const LOG_NUM_SHARES: usize = 2;

        let friveil = TestFriVeil::new(LOG_INV_RATE, NUM_TEST_QUERIES, N_VARS, LOG_NUM_SHARES);

        assert_eq!(friveil.log_inv_rate, LOG_INV_RATE);
        assert_eq!(friveil.num_test_queries, NUM_TEST_QUERIES);
        assert_eq!(friveil.n_vars, N_VARS);
        assert_eq!(friveil.log_num_shares, LOG_NUM_SHARES);
    }

    #[test]
    fn test_calculate_evaluation_point_random() {
        const N_VARS: usize = 8;
        let friveil = TestFriVeil::new(1, 3, N_VARS, 2);

        let result = friveil.calculate_evaluation_point_random();
        assert!(result.is_ok());

        let evaluation_point = result.unwrap();
        assert_eq!(evaluation_point.len(), N_VARS);

        // Test deterministic behavior with fixed seed
        let result2 = friveil.calculate_evaluation_point_random();
        assert!(result2.is_ok());
        let evaluation_point2 = result2.unwrap();
        assert_eq!(evaluation_point, evaluation_point2);
    }

    #[test]
    fn test_field_conversion_methods() {
        let friveil = TestFriVeil::new(1, 3, 8, 2);

        // Test small to large field conversion
        let small_field_values: Vec<B1> = vec![B1::ZERO, B1::ONE, B1::ZERO, B1::ONE];
        let large_field_values: Vec<B128> = friveil.lift_small_to_large_field(&small_field_values);

        assert_eq!(large_field_values.len(), small_field_values.len());
        assert_eq!(large_field_values[0], B128::from(B1::ZERO));
        assert_eq!(large_field_values[1], B128::from(B1::ONE));

        // Test large to small field conversion
        let test_large_values: Vec<B128> = vec![B128::from(42u128), B128::from(100u128)];
        let converted_small: Vec<B1> =
            friveil.large_field_mle_to_small_field_mle(&test_large_values);

        // Each B128 should expand to 128 B1 elements
        assert_eq!(converted_small.len(), test_large_values.len() * 128);
    }

    #[test]
    fn test_initialize_fri_context() {
        let friveil = TestFriVeil::new(1, 3, 12, 2);

        // Create test data
        let test_data = create_test_data(1024); // 1KB test data
        let packed_mle_values = FriVeilUtils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let result = friveil.initialize_fri_context(packed_mle_values.packed_mle.clone());
        assert!(result.is_ok());

        let (fri_params, _ntt) = result.unwrap();

        // Verify FRI parameters are reasonable
        assert_eq!(fri_params.rs_code().log_inv_rate(), friveil.log_inv_rate);
        assert_eq!(fri_params.n_test_queries(), friveil.num_test_queries);
    }

    #[test]
    fn test_commit_and_inclusion_proofs() {
        let friveil = TestFriVeil::new(1, 3, 12, 2);

        // Create test data
        let test_data = create_test_data(1024);
        let packed_mle_values = FriVeilUtils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        // Test commit
        let commit_result = friveil.commit(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
        );
        assert!(commit_result.is_ok());

        let commit_output = commit_result.unwrap();
        assert!(!commit_output.commitment.is_empty());
        assert!(!commit_output.codeword.is_empty());

        // Test inclusion proofs for first few elements
        for i in 0..std::cmp::min(5, commit_output.codeword.len()) {
            let value = commit_output.codeword[i];

            // Generate inclusion proof
            let inclusion_proof_result = friveil.inclusion_proof(&commit_output.committed, i);
            assert!(inclusion_proof_result.is_ok());

            let mut inclusion_proof = inclusion_proof_result.unwrap();

            // Verify inclusion proof
            let verify_result = friveil.verify_inclusion_proof(
                &mut inclusion_proof,
                &[value],
                i,
                &fri_params,
                &commit_output.committed,
            );
            assert!(
                verify_result.is_ok(),
                "Inclusion proof verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_calculate_evaluation_claim() {
        let test_data = create_test_data(1024 * 1024); // 1mb test data
        let packed_mle_values = FriVeilUtils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);

        let evaluation_point = friveil
            .calculate_evaluation_point_random()
            .expect("Failed to generate evaluation point");

        let result =
            friveil.calculate_evaluation_claim(&packed_mle_values.packed_values, &evaluation_point);
        assert!(result.is_ok());

        let evaluation_claim = result.unwrap();
        // The evaluation claim should be a valid field element
        assert_ne!(evaluation_claim, B128::default()); // Should not be zero for random inputs
    }

    #[test]
    fn test_full_prove_verify_workflow() {
        // Create test data
        let test_data = create_test_data(1024 * 1024); // 2KB test data
        let packed_mle_values = FriVeilUtils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);
        // Initialize FRI context
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        // Generate evaluation point
        let evaluation_point = friveil
            .calculate_evaluation_point_random()
            .expect("Failed to generate evaluation point");

        // Commit to MLE
        let commit_output = friveil
            .commit(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
            )
            .expect("Failed to commit");

        // Generate proof
        let prove_result = friveil.prove(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
            &commit_output,
            &evaluation_point,
        );
        assert!(prove_result.is_ok());

        let mut verifier_transcript = prove_result.unwrap();

        // Calculate evaluation claim
        let evaluation_claim = friveil
            .calculate_evaluation_claim(&packed_mle_values.packed_values, &evaluation_point)
            .expect("Failed to calculate evaluation claim");

        // Verify proof
        let verify_result = friveil.verify_evaluation(
            &mut verifier_transcript,
            evaluation_claim,
            &evaluation_point,
            &fri_params,
        );
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result
        );
    }

    #[test]
    fn test_invalid_verification_fails() {
        // Create test data
        let test_data = create_test_data(512);
        let packed_mle_values = FriVeilUtils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");
        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        let commit_output = friveil
            .commit(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
            )
            .expect("Failed to commit");

        let evaluation_point = friveil
            .calculate_evaluation_point_random()
            .expect("Failed to generate evaluation point");

        let mut verifier_transcript = friveil
            .prove(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
                &commit_output,
                &evaluation_point,
            )
            .expect("Failed to generate proof");

        // Use wrong evaluation claim (should cause verification to fail)
        let wrong_evaluation_claim = B128::from(42u128);

        let verify_result = friveil.verify_evaluation(
            &mut verifier_transcript,
            wrong_evaluation_claim,
            &evaluation_point,
            &fri_params,
        );

        // Verification should fail with wrong claim
        assert!(
            verify_result.is_err(),
            "Verification should fail with wrong evaluation claim"
        );
    }
}
