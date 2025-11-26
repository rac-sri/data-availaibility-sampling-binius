//! FRI-Veil: FRI-based Vector Commitment Scheme with Data Availability Sampling
//!
//! This module implements a polynomial commitment scheme using FRI Binius (Fast Reed-Solomon
//! Interactive Oracle Proofs) combined with Merkle tree commitments. It provides:
//!
//! - **Polynomial Commitment**: Commit to multilinear polynomials over binary fields
//! - **Reed-Solomon Encoding**: Error correction codes for data availability
//! - **Merkle Tree Commitments**: Cryptographic commitments to codewords
//! - **Inclusion Proofs**: Prove that specific values are part of the commitment
//! - **Data Availability Sampling**: Verify data availability by sampling random positions
//!
//! # Architecture
//!
//! ```text
//! Data → MLE → FRI Context → Commitment → Encoding/Decoding
//!                                ↓
//!                         Merkle Tree Root
//!                                ↓
//!                    Inclusion Proofs + Sampling
//! ```

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

/// Default FRI-Veil configuration using 128-bit binary fields
///
/// This type alias provides a convenient default configuration with:
/// - Packed field: B128 (128-bit binary field)
/// - Merkle tree: Binary Merkle tree with standard hash functions
/// - NTT: Neighbors-last multi-threaded NTT implementation
pub type FriVeilDefault = FriVeil<
    'static,
    B128,
    BinaryMerkleTreeScheme<B128, StdDigest, StdCompression>,
    NeighborsLastMultiThread<GenericPreExpanded<B128>>,
>;

/// FRI-Veil polynomial commitment scheme
///
/// Generic over:
/// - `'a`: Lifetime for NTT reference
/// - `P`: Packed field type for efficient operations
/// - `VCS`: Vector commitment scheme (Merkle tree)
/// - `NTT`: Number Theoretic Transform implementation
///
/// # Type Parameters
///
/// - `P`: Must be a packed field over B128 scalars with extension field properties
/// - `VCS`: Merkle tree scheme for vector commitments
/// - `NTT`: Additive NTT over B128 field, used for Reed-Solomon encoding
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
    /// Create a new FRI-Veil instance
    ///
    /// # Arguments
    ///
    /// * `log_inv_rate` - Logarithm of Reed-Solomon inverse rate
    ///   - 1 means 2x expansion (50% redundancy)
    ///   - 2 means 4x expansion (75% redundancy)
    /// * `num_test_queries` - Number of FRI test queries (security parameter)
    ///   - Typical values: 64-128 for good security
    /// * `n_vars` - Number of variables in the multilinear polynomial
    /// * `log_num_shares` - Logarithm of Merkle tree shares
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

    /// Initialize FRI protocol context and NTT for Reed-Solomon encoding
    ///
    /// This sets up the necessary parameters for FRI-based polynomial commitment:
    /// - Creates Reed-Solomon code with specified expansion rate
    /// - Configures FRI folding parameters (arities)
    /// - Initializes NTT domain for efficient encoding/decoding
    ///
    /// # Arguments
    ///
    /// * `packed_buffer` - Packed field buffer containing the polynomial evaluations
    ///
    /// # Returns
    ///
    /// * `Ok((FRIParams, NTT))` - FRI parameters and NTT instance
    /// * `Err(String)` - Error message if initialization fails
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

    /// Generate a random evaluation point for polynomial evaluation
    ///
    /// Creates a random point in the n-dimensional space for evaluating
    /// the multilinear polynomial. Uses a fixed seed for reproducibility.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<P::Scalar>)` - Random evaluation point with `n_vars` coordinates
    /// * `Err(String)` - Error message (currently never fails)
    ///
    /// # Note
    ///
    /// Uses a fixed seed `[0; 32]` for deterministic behavior in tests.
    /// For production use, consider using a cryptographically secure RNG.
    pub fn calculate_evaluation_point_random(&self) -> Result<Vec<P::Scalar>, String> {
        let mut rng = StdRng::from_seed([0; 32]);
        let evaluation_point: Vec<P::Scalar> = repeat_with(|| P::Scalar::random(&mut rng))
            .take(self.n_vars)
            .collect();
        Ok(evaluation_point)
    }

    /// Calculate the evaluation claim for a polynomial at a given point
    ///
    /// Computes the multilinear extension evaluation using the equality polynomial.
    /// This is the claimed value that the prover will prove is correct.
    ///
    /// # Arguments
    ///
    /// * `data` - Polynomial evaluations (coefficients in evaluation form)
    /// * `evaluation_point` - Point at which to evaluate the polynomial
    ///
    /// # Returns
    ///
    /// * `Ok(P::Scalar)` - The evaluation result (claim)
    /// * `Err(String)` - Error if dimensions don't match
    ///
    /// # Algorithm
    ///
    /// Uses the equality polynomial to compute:
    /// ```text
    /// eval = Σ data[i] * eq(i, evaluation_point)
    /// ```
    /// where `eq` is the multilinear equality polynomial
    pub fn calculate_evaluation_claim(
        &self,
        values: &[P::Scalar],
        evaluation_point: &[P::Scalar],
    ) -> Result<P::Scalar, String> {
        // Convert to small field representation for efficient computation
        let lifted_small_field_mle = self.lift_small_to_large_field::<B1, P::Scalar>(
            &self.large_field_mle_to_small_field_mle::<B1, P::Scalar>(values),
        );

        // Compute inner product with equality polynomial
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

    /// Generate a polynomial commitment and codeword
    ///
    /// Creates a Merkle tree commitment to the Reed-Solomon encoded codeword.
    /// This is the core commitment phase of the polynomial commitment scheme.
    ///
    /// # Arguments
    ///
    /// * `packed_mle` - Packed multilinear extension to commit to
    /// * `fri_params` - FRI protocol parameters
    /// * `ntt` - NTT instance for encoding
    ///
    /// # Returns
    ///
    /// * `Ok(CommitOutput)` - Contains:
    ///   - `codeword`: Reed-Solomon encoded values
    ///   - `commitment`: Merkle root (32 bytes)
    ///   - `committed`: Merkle tree structure for proof generation
    /// * `Err(String)` - Error message if commitment fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let commit_output = friveil.commit(packed_mle, fri_params, &ntt)?;
    /// println!("Commitment: {:?}", commit_output.commitment);
    /// ```
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

        // Convert the digest type to Vec<u8> for easier handling
        Ok(CommitOutput {
            codeword: commit_output.codeword,
            commitment: commit_output.commitment.to_vec(),
            committed: commit_output.committed,
        })
    }

    /// Generate an evaluation proof for the committed polynomial
    ///
    /// Creates a FRI-based proof that the polynomial evaluates to a specific
    /// value at the given evaluation point. This proof can be verified without
    /// access to the full polynomial.
    ///
    /// # Arguments
    ///
    /// * `packed_mle` - The original packed multilinear extension
    /// * `fri_params` - FRI protocol parameters
    /// * `ntt` - NTT instance for encoding
    /// * `commit_output` - Output from the commit phase
    /// * `evaluation_point` - Point at which to prove evaluation
    ///
    /// # Returns
    ///
    /// * `Ok(VerifierTranscript)` - Transcript containing the proof
    /// * `Err(String)` - Error message if proof generation fails
    ///
    /// # Process
    ///
    /// 1. Initialize prover transcript with commitment
    /// 2. Run FRI protocol to generate proof
    /// 3. Convert to verifier transcript for verification
    ///
    /// # Example
    ///
    /// ```ignore
    /// let transcript = friveil.prove(
    ///     packed_mle,
    ///     fri_params,
    ///     &ntt,
    ///     &commit_output,
    ///     &evaluation_point,
    /// )?;
    /// ```
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

        // Write commitment to transcript
        prover_transcript
            .message()
            .write_bytes(&commit_output.commitment);

        // Generate FRI proof
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

    /// Encode data using Reed-Solomon code with NTT
    ///
    /// This is a helper function to observe NTT encoding behavior outside
    /// the `commit` function. Applies Reed-Solomon encoding to expand data
    /// with redundancy for error correction.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to encode
    /// * `fri_params` - FRI parameters containing Reed-Solomon code configuration
    /// * `ntt` - NTT instance for efficient encoding
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<P::Scalar>)` - Encoded codeword with redundancy
    /// * `Err(String)` - Error message if encoding fails
    ///
    /// # Note
    ///
    /// This function is marked `#[allow(dead_code)]` as it's primarily used
    /// for testing and debugging. The `commit` function handles encoding internally.
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

    /// Lift elements from a small field to a large extension field
    ///
    /// Converts field elements from a base field `F` to an extension field `FE`.
    /// This is used for efficient computation in the extension field.
    ///
    /// # Type Parameters
    ///
    /// * `F` - Base field type
    /// * `FE` - Extension field type (must extend `F`)
    ///
    /// # Arguments
    ///
    /// * `small_field_elms` - Elements in the base field
    ///
    /// # Returns
    ///
    /// Vector of elements lifted to the extension field
    pub fn lift_small_to_large_field<F, FE>(&self, small_field_elms: &[F]) -> Vec<FE>
    where
        F: Field,
        FE: Field + ExtensionField<F>,
    {
        small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
    }

    /// Convert large field MLE to small field MLE representation
    ///
    /// Decomposes extension field elements into their base field components.
    /// This is the inverse operation of `lift_small_to_large_field`.
    ///
    /// # Type Parameters
    ///
    /// * `F` - Base field type
    /// * `FE` - Extension field type (must extend `F`)
    ///
    /// # Arguments
    ///
    /// * `large_field_mle` - MLE in extension field
    ///
    /// # Returns
    ///
    /// Vector of base field elements (flattened representation)
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

    /// Verify an evaluation proof for the committed polynomial
    ///
    /// Verifies that a polynomial evaluates to a claimed value at a given point
    /// using the FRI-based proof in the transcript.
    ///
    /// # Arguments
    ///
    /// * `verifier_transcript` - Transcript containing the proof
    /// * `evaluation_claim` - Claimed evaluation result
    /// * `evaluation_point` - Point at which polynomial was evaluated
    /// * `fri_params` - FRI protocol parameters
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Proof is valid
    /// * `Err(String)` - Proof is invalid or verification failed
    ///
    /// # Process
    ///
    /// 1. Extract commitment from transcript
    /// 2. Run FRI verification protocol
    /// 3. Check consistency with claimed evaluation
    fn verify_evaluation(
        &self,
        verifier_transcript: &mut VerifierTranscript<StdChallenger>,
        evaluation_claim: P::Scalar,
        evaluation_point: &[P::Scalar],
        fri_params: &FRIParams<P::Scalar>,
    ) -> Result<(), String> {
        // Extract commitment from transcript
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

    /// Generate a Merkle inclusion proof for a specific codeword position
    ///
    /// Creates a proof that a value at a given index is part of the committed
    /// codeword. This is used for data availability sampling.
    ///
    /// # Arguments
    ///
    /// * `committed` - Merkle tree commitment structure
    /// * `index` - Position in the codeword to prove
    ///
    /// # Returns
    ///
    /// * `Ok(VerifierTranscript)` - Transcript containing the inclusion proof
    /// * `Err(String)` - Error generating the proof
    ///
    /// # Example
    ///
    /// ```ignore
    /// let proof = friveil.inclusion_proof(&commit_output.committed, 42)?;
    /// ```
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

    /// Verify a Merkle inclusion proof for a codeword value
    ///
    /// Verifies that a value at a specific index is correctly committed
    /// in the Merkle tree. This is the verification counterpart to `inclusion_proof`.
    ///
    /// # Arguments
    ///
    /// * `verifier_transcript` - Transcript containing the inclusion proof
    /// * `data` - Value(s) to verify
    /// * `index` - Position in the codeword
    /// * `fri_params` - FRI parameters (for context)
    /// * `commitment` - Merkle root commitment (32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Inclusion proof is valid
    /// * `Err(String)` - Proof is invalid or verification failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// friveil.verify_inclusion_proof(
    ///     &mut proof,
    ///     &[value],
    ///     index,
    ///     &fri_params,
    ///     commitment_bytes,
    /// )?;
    /// ```
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

    /// Decode a Reed-Solomon encoded codeword back to original data
    ///
    /// Applies inverse Reed-Solomon transformation to recover the original
    /// data from the encoded codeword. This is the inverse of `encode_codeword`.
    ///
    /// # Arguments
    ///
    /// * `codeword` - Reed-Solomon encoded codeword
    /// * `fri_params` - FRI parameters containing RS code configuration
    /// * `ntt` - NTT instance for efficient decoding
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<P::Scalar>)` - Decoded original data
    /// * `Err(String)` - Error message if decoding fails
    ///
    /// # Process
    ///
    /// 1. Calculate expected output length
    /// 2. Apply inverse NTT transformation
    /// 3. Trim to original data size (remove redundancy)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let decoded = friveil.decode_codeword(&encoded, fri_params, &ntt)?;
    /// assert_eq!(decoded, original_data);
    /// ```
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
            // Safety: decode_batch guarantees all elements are initialized on success
            decoded.set_len(len);
        }

        // Trim to original data size (remove redundancy)
        let trim_len = 1 << (rs_code.log_dim() + fri_params.log_batch_size() - P::LOG_WIDTH);
        decoded.resize(trim_len, P::Scalar::zero());
        Ok(decoded)
    }

    /// Extract commitment from verifier transcript
    ///
    /// Helper function to read the commitment bytes from a transcript.
    /// This is used internally for verification workflows.
    ///
    /// # Arguments
    ///
    /// * `verifier_transcript` - Transcript containing the commitment
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Commitment bytes
    /// * `Err(String)` - Error reading from transcript
    ///
    /// # Note
    ///
    /// Marked as `#[allow(dead_code)]` as it's currently unused but
    /// may be useful for future transcript manipulation.
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

    /// Low-level batch decoding using inverse NTT
    ///
    /// Performs the actual Reed-Solomon decoding operation using inverse NTT.
    /// This is called by `decode_codeword` and handles the core transformation.
    ///
    /// # Arguments
    ///
    /// * `log_len` - Logarithm of codeword length
    /// * `log_inv` - Logarithm of inverse rate (redundancy factor)
    /// * `log_batch_size` - Logarithm of batch size
    /// * `ntt` - NTT instance for transformation
    /// * `data` - Input codeword data
    /// * `output` - Uninitialized output buffer
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Decoding successful, output buffer is initialized
    /// * `Err(String)` - Decoding failed
    ///
    /// # Safety
    ///
    /// On success, guarantees that all elements in `output` are properly initialized.
    ///
    /// # Implementation Details
    ///
    /// 1. Validates input dimensions
    /// 2. Copies data to output buffer
    /// 3. Applies inverse NTT with appropriate skip parameters
    /// 4. Handles both packed and unpacked field representations
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
                    let mut u = code.get(idx0);
                    let mut v = code.get(idx1);

                    v += u;
                    u += v * twiddle;
                    code.set(idx0, u);
                    code.set(idx1, v);
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
        use tracing::Level;

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
