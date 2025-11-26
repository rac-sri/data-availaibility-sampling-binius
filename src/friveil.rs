use crate::traits::{FriVeilSampling, FriVeilUtils};
pub use binius_field::PackedField;
use binius_field::{ExtensionField, Field, PackedExtension, Random};
use binius_math::{
    BinarySubspace, FieldBuffer, FieldSliceMut, ReedSolomonCode,
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
use binius_transcript::{Buf, ProverTranscript, VerifierTranscript};
pub use binius_verifier::config::B128;
use binius_verifier::{
    config::{B1, StdChallenger},
    fri::FRIParams,
    hash::{StdCompression, StdDigest},
    merkle_tree::{BinaryMerkleTreeScheme, MerkleTreeScheme},
    pcs::verify,
};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};
use std::{iter::repeat_with, marker::PhantomData, mem::MaybeUninit};
use tracing::debug;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
            vec![2; packed_buffer.log_len() / 2]
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
            << (rs_code.log_dim() + fri_params.log_batch_size() - P::LOG_WIDTH
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

impl<'a, P, VCS, NTT> FriVeilSampling<P, NTT> for FriVeil<'a, P, VCS, NTT>
where
    NTT: AdditiveNTT<Field = B128> + Sync,
    P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
    VCS: MerkleTreeScheme<P::Scalar>,
{
    /// Decode a Reed-Solomon codeword with error correction for missing points
    /// This implements proper Reed-Solomon erasure decoding using polynomial interpolation
    /// Note: Extremely naive algorithm, primarily for soundness guarantee demonstration.
    /// # Performance
    /// - When compiled with `--features parallel`, uses rayon for parallel processing
    /// - When compiled without the parallel feature, uses sequential processing
    fn reconstruct_codeword_naive(
        &self,
        corrupted_codeword: &mut [P::Scalar],
        corrupted_indices: &[usize],
    ) -> Result<(), String> {
        let n = corrupted_codeword.len();
        let domain = (0..corrupted_codeword.len())
            .map(|i| P::Scalar::from(i as u128))
            .collect::<Vec<_>>();
        if corrupted_indices.is_empty() {
            return Ok(());
        }

        // Collect known points (x_j, y_j)
        let known: Vec<(P::Scalar, P::Scalar)> = (0..n)
            .filter(|i| !corrupted_indices.contains(i))
            .map(|i| (domain[i], corrupted_codeword[i]))
            .collect();

        let k = known.len();
        if k == 0 {
            return Err("No known points available for reconstruction".into());
        }

        // For each erased position, interpolate and evaluate
        #[cfg(feature = "parallel")]
        {
            // Parallel version using rayon
            let reconstructed_values: Vec<(usize, P::Scalar)> = corrupted_indices
                .par_iter()
                .map(|&missing| {
                    debug!("Calculating value for missing index: {}", missing);
                    let x_e = domain[missing];

                    let mut value = P::Scalar::zero();

                    for j in 0..k {
                        let (x_j, y_j) = known[j];

                        // Compute L_j(x_e)
                        let mut l_j = P::Scalar::ONE;
                        for m in 0..k {
                            if m == j {
                                continue;
                            }
                            let (x_m, _) = known[m];
                            l_j = l_j * (x_e - x_m) * (x_j - x_m).invert().unwrap();
                        }

                        value = value + y_j * l_j;
                    }

                    debug!(
                        "Reconstructed value for missing index {}: {:?}",
                        missing, value
                    );
                    (missing, value)
                })
                .collect();

            // Apply the reconstructed values to the codeword
            for (missing, value) in reconstructed_values {
                corrupted_codeword[missing] = value;
            }
        }

        #[cfg(not(feature = "parallel"))]
        {
            // Sequential version
            for &missing in corrupted_indices {
                debug!("Calculating value for missing index: {}", missing);
                let x_e = domain[missing];

                let mut value = P::Scalar::zero();

                for j in 0..k {
                    let (x_j, y_j) = known[j];

                    // Compute L_j(x_e)
                    let mut l_j = P::Scalar::ONE;
                    for m in 0..k {
                        if m == j {
                            continue;
                        }
                        let (x_m, _) = known[m];
                        l_j = l_j * (x_e - x_m) * (x_j - x_m).invert().unwrap();
                    }

                    value = value + y_j * l_j;
                }

                debug!(
                    "Reconstructed value for missing index {}: {:?}",
                    missing, value
                );
                corrupted_codeword[missing] = value;
            }
        }

        Ok(())
    }

    fn verify_evaluation(
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

    fn inclusion_proof(
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

    fn verify_inclusion_proof(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        data: &[P::Scalar],
        index: usize,
        fri_params: &FRIParams<P::Scalar>,
        commitment: [u8; 32],
    ) -> Result<(), String> {
        let tree_depth = fri_params.rs_code().log_len();
        self.merkle_prover
            .scheme()
            .verify_opening(
                index,
                data,
                0,
                tree_depth,
                &[commitment.into()],
                &mut verifier_transcript.message(),
            )
            .map_err(|e| e.to_string())
    }

    fn decode_codeword(
        &self,
        codeword: &[P::Scalar],
        fri_params: FRIParams<P::Scalar>,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
    ) -> Result<Vec<P::Scalar>, String> {
        let rs_code = fri_params.rs_code();
        let len = 1 << (rs_code.log_len() + fri_params.log_batch_size() - P::LOG_WIDTH);

        let mut decoded = Vec::with_capacity(len);
        self.decode_batch(
            rs_code.log_len(),
            rs_code.log_inv_rate(),
            fri_params.log_batch_size(),
            ntt,
            codeword.as_ref(),
            decoded.spare_capacity_mut(),
        )
        .map_err(|e| e.to_string())?;

        unsafe {
            // Safety: encode_ext_batch guarantees all elements are initialized on success
            decoded.set_len(len);
        }

        let trim_len = 1 << (rs_code.log_dim() + fri_params.log_batch_size() - P::LOG_WIDTH);
        decoded.resize(trim_len, P::Scalar::zero());
        Ok(decoded)
    }

    #[allow(dead_code)]
    fn extract_commitment(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
    ) -> Result<Vec<u8>, String> {
        verifier_transcript
            .message()
            .read()
            .map_err(|e| e.to_string())
    }

    fn decode_batch(
        &self,
        log_len: usize,
        log_inv: usize,
        log_batch_size: usize,
        ntt: &NeighborsLastMultiThread<GenericPreExpanded<P::Scalar>>,
        data: &[P::Scalar],
        output: &mut [MaybeUninit<P::Scalar>],
    ) -> Result<(), String> {
        let data_log_len = log_len + log_batch_size;

        let expected_data_len = if data_log_len >= P::LOG_WIDTH {
            1 << (data_log_len - P::LOG_WIDTH)
        } else {
            1
        };

        if data.len() != expected_data_len {
            return Err(format!(
                "Unexpected data length: {} {} ",
                expected_data_len,
                data.len()
            ));
        }

        let _scope = tracing::trace_span!(
            "Reed-Solomon encode",
            log_len = log_len,
            log_batch_size = log_batch_size,
        )
        .entered();

        let data_portion_len = data.len();

        for i in 0..data_portion_len {
            output[i].write(data[i]);
        }

        for i in data_portion_len..output.len() {
            output[i].write(P::Scalar::zero());
        }

        let output_initialized =
            unsafe { uninit::out_ref::Out::<[P::Scalar]>::from(output).assume_init() };
        let mut code = FieldSliceMut::from_slice(log_len + log_batch_size, output_initialized)
            .map_err(|e| e.to_string())?;

        let skip_early = log_inv;
        let skip_late = log_batch_size;

        // TODO: create an optimised version PR to binius 64 for inverse_ntt
        let log_d = code.log_len();
        use binius_math::ntt::DomainContext;
        for layer in (skip_early..(log_d - skip_late)).rev() {
            let num_blocks = 1 << layer;
            let block_size_half = 1 << (log_d - layer - 1);
            for block in 0..num_blocks {
                let twiddle = ntt.domain_context().twiddle(layer, block);
                let block_start = block << (log_d - layer);
                for idx0 in block_start..(block_start + block_size_half) {
                    let idx1 = block_size_half | idx0;
                    // perform butterfly
                    let mut u = code.get(idx0).unwrap();
                    let mut v = code.get(idx1).unwrap();

                    v += u;
                    u += v * twiddle;
                    code.set(idx0, u).unwrap();
                    code.set(idx1, v).unwrap();
                }
            }
        }

        Ok(())
    }
}

impl FriVeilUtils for FriVeilDefault {
    fn get_transcript_bytes(&self, transcript: &VerifierTranscript<StdChallenger>) -> Vec<u8> {
        let mut cloned = transcript.clone();
        let mut message_reader = cloned.message();
        let buffer = message_reader.buffer();
        let remaining = buffer.remaining();

        if remaining == 0 {
            return Vec::new();
        }

        // Read all remaining bytes
        let mut bytes = vec![0u8; remaining];
        buffer.copy_to_slice(&mut bytes);
        bytes
    }
    fn reconstruct_transcript_from_bytes(
        &self,
        bytes: Vec<u8>,
    ) -> VerifierTranscript<StdChallenger> {
        VerifierTranscript::new(StdChallenger::default(), bytes)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::poly::Utils;
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
        let packed_mle_values = Utils::<B128>::new()
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
        let packed_mle_values = Utils::<B128>::new()
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

        let commitment_bytes: [u8; 32] = commit_output
            .commitment
            .to_vec()
            .try_into()
            .expect("We know commitment size is 32 bytes");
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
                commitment_bytes,
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
        let packed_mle_values = Utils::<B128>::new()
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
        let packed_mle_values = Utils::<B128>::new()
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
        let packed_mle_values = Utils::<B128>::new()
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

    #[test]
    fn test_data_availability_sampling() {
        use rand::{SeedableRng, rngs::StdRng, seq::index::sample};
        use tracing::{Level, debug, info, span, warn};

        // Initialize logging for the test
        let _ = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .try_init();

        // Create test data
        let test_data = create_test_data(1024 * 1024); // 1MB test data
        let packed_mle_values = Utils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);

        // Initialize FRI context
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        // Commit to MLE
        let commit_output = friveil
            .commit(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
            )
            .expect("Failed to commit");

        let total_samples = commit_output.codeword.len();
        let sample_size = total_samples / 2;
        let indices =
            sample(&mut StdRng::from_seed([0; 32]), total_samples, sample_size).into_vec();
        let commitment_bytes: [u8; 32] = commit_output
            .commitment
            .to_vec()
            .try_into()
            .expect("We know commitment size is 32 bytes");

        let mut successful_samples = 0;
        let mut failed_samples = Vec::new();

        for &sample_index in indices.iter() {
            match friveil.inclusion_proof(&commit_output.committed, sample_index) {
                Ok(mut inclusion_proof) => {
                    let value = commit_output.codeword[sample_index];
                    match friveil.verify_inclusion_proof(
                        &mut inclusion_proof,
                        &[value],
                        sample_index,
                        &fri_params,
                        commitment_bytes,
                    ) {
                        Ok(_) => {
                            successful_samples += 1;
                        }
                        Err(e) => {
                            failed_samples
                                .push((sample_index, format!("Verification failed: {}", e)));
                        }
                    }
                }
                Err(e) => {
                    failed_samples.push((
                        sample_index,
                        format!("Inclusion proof generation failed: {}", e),
                    ));
                }
            }
        }

        assert_eq!(failed_samples.len(), 0, "Some samples failed verification");
        assert_eq!(
            successful_samples, sample_size,
            "Not all samples were verified"
        );

        println!("Successfully verified {} samples", successful_samples);
    }

    #[test]
    fn test_codeword_decode() {
        // Create test data
        let test_data = create_test_data(512);
        let packed_mle_values = Utils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);

        // Initialize FRI context
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        // Encode codeword
        let encoded_codeword = friveil
            .encode_codeword(&packed_mle_values.packed_values, fri_params.clone(), &ntt)
            .expect("Failed to encode codeword");

        // Decode codeword
        let decoded_codeword = friveil
            .decode_codeword(&encoded_codeword, fri_params.clone(), &ntt)
            .expect("Failed to decode codeword");

        // Verify decoded codeword matches original values
        assert_eq!(
            decoded_codeword, packed_mle_values.packed_values,
            "Decoded codeword should match original packed values"
        );

        println!("✅ Codeword decode test passed");
    }

    #[test]
    fn test_error_correction_reconstruction() {
        use rand::{SeedableRng, rngs::StdRng, seq::index::sample};

        // Create test data
        let test_data = create_test_data(2048);
        let packed_mle_values = Utils::<B128>::new()
            .bytes_to_packed_mle(&test_data)
            .expect("Failed to create packed MLE");

        let friveil = TestFriVeil::new(1, 3, packed_mle_values.total_n_vars, 3);

        // Initialize FRI context
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.clone())
            .expect("Failed to initialize FRI context");

        // Encode codeword
        let encoded_codeword = friveil
            .encode_codeword(&packed_mle_values.packed_values, fri_params.clone(), &ntt)
            .expect("Failed to encode codeword");

        // Corrupt the codeword
        let mut corrupted_codeword = encoded_codeword.clone();
        let total_elements = corrupted_codeword.len();
        let corruption_percentage = 0.1;

        // Corrupt random elements
        let num_corrupted = (total_elements as f64 * corruption_percentage) as usize;
        let mut rng = StdRng::seed_from_u64(42);
        let corrupted_indices = sample(&mut rng, total_elements, num_corrupted).into_vec();

        for &index in &corrupted_indices {
            corrupted_codeword[index] = B128::zero();
        }

        // Verify corruption happened
        assert_ne!(
            corrupted_codeword, encoded_codeword,
            "Codeword should be corrupted"
        );

        // Reconstruct corrupted codeword
        friveil
            .reconstruct_codeword_naive(&mut corrupted_codeword, &corrupted_indices)
            .expect("Failed to reconstruct codeword");

        // Verify reconstruction succeeded
        assert_eq!(
            corrupted_codeword, encoded_codeword,
            "Reconstructed codeword should match original encoded codeword"
        );

        // Decode the reconstructed codeword to verify it's correct
        let decoded_reconstructed = friveil
            .decode_codeword(&corrupted_codeword, fri_params.clone(), &ntt)
            .expect("Failed to decode reconstructed codeword");

        // Verify decoded reconstructed codeword matches original values
        assert_eq!(
            decoded_reconstructed, packed_mle_values.packed_values,
            "Decoded reconstructed codeword should match original packed values"
        );

        println!(
            "✅ Error correction reconstruction test passed: {} elements, {:.1}% corruption",
            total_elements,
            corruption_percentage * 100.0
        );
    }
}
