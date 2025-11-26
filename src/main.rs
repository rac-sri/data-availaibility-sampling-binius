use crate::{
    friveil::{B128, FriVeilDefault, PackedField},
    poly::Utils,
    traits::{FriVeilSampling, FriVeilUtils},
};
use rand::{SeedableRng, rngs::StdRng, seq::index::sample};
use std::time::Instant;
use tracing::{Level, debug, error, info, span, warn};

mod friveil;
mod poly;
mod traits;

fn main() {
    // Initialize enhanced logging with structured output, filtering out verbose internal logs
    use tracing_subscriber::filter::EnvFilter;

    let filter = EnvFilter::new("info")
        .add_directive("binius_transcript=error".parse().unwrap())
        .add_directive("transcript=error".parse().unwrap());

    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_env_filter(filter)
        .init();

    const LOG_INV_RATE: usize = 1;
    // Security parameter: number of queries to perform in the FRI protocol
    const NUM_TEST_QUERIES: usize = 128;
    const DATA_SIZE_MB: usize = 16;

    info!("🚀 Starting Binius Data Availability Sampling Scheme");
    info!("📋 Configuration:");
    info!("   - Reed-Solomon inverse rate (log2): {}", LOG_INV_RATE);
    info!("   - FRI test queries: {}", NUM_TEST_QUERIES);
    info!("   - Data size: {} MB", DATA_SIZE_MB);

    // Create arbitrary (nonzero, patterned) data instead of all zeroes.
    let _span = span!(Level::INFO, "data_generation").entered();
    info!("📊 Phase 1: Generating test data ({} MB)", DATA_SIZE_MB);
    let random_data_bytes: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    info!(
        "✅ Generated {} bytes of patterned test data",
        random_data_bytes.len()
    );
    drop(_span);

    let _span = span!(Level::INFO, "mle_conversion").entered();
    info!("🔄 Phase 2: Converting bytes to multilinear extension");
    let start = Instant::now();
    let packed_mle_values = Utils::new()
        .bytes_to_packed_mle(&random_data_bytes)
        .unwrap();

    let conversion_time = start.elapsed().as_millis();
    info!("✅ MLE conversion completed in {} ms", conversion_time);
    info!(
        "   - Total variables (n_vars): {}",
        packed_mle_values.total_n_vars
    );
    info!(
        "   - Packed values count: {}",
        packed_mle_values.packed_values.len()
    );

    drop(_span);

    let _span = span!(Level::INFO, "fri_initialization").entered();
    info!("🔧 Phase 3: Initializing FRI-based polynomial commitment scheme");
    let start = Instant::now();
    let friveil = FriVeilDefault::new(
        LOG_INV_RATE,
        NUM_TEST_QUERIES,
        packed_mle_values.total_n_vars,
        80, // log_num_shares
    );
    let init_time = start.elapsed().as_millis();
    info!("✅ FRIVeil context initialized in {} ms", init_time);

    let start = Instant::now();
    info!("🎲 Generating random evaluation point");
    let evaluation_point = friveil.calculate_evaluation_point_random().unwrap();
    let eval_time = start.elapsed().as_millis();
    info!("✅ Evaluation point generated in {} ms", eval_time);
    info!(
        "   - Evaluation point dimensions: {}",
        evaluation_point.len()
    );
    drop(_span);

    let _span = span!(Level::INFO, "fri_context_setup").entered();
    info!("⚙️  Setting up FRI protocol parameters");
    let start = Instant::now();
    let (fri_params, ntt) = friveil
        .initialize_fri_context(packed_mle_values.packed_mle.clone())
        .unwrap();
    let context_time = start.elapsed().as_millis();
    info!("✅ FRI context setup completed in {} ms", context_time);
    info!(
        "   - Reed-Solomon code length (log2): {}",
        fri_params.rs_code().log_len()
    );
    info!(
        "   - Reed-Solomon inverse rate (log2): {}",
        fri_params.rs_code().log_inv_rate()
    );
    info!("   - FRI test queries: {}", fri_params.n_test_queries());
    drop(_span);

    let _span = span!(Level::INFO, "vector_commitment_and_codeword").entered();
    info!("🔒 Phase 4: Generating vector commitment and codeword");
    let start = Instant::now();
    let commit_output = friveil
        .commit(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
        )
        .unwrap();
    let commit_time = start.elapsed().as_millis();

    info!(
        "✅ Vector commitment and codeword generated in {} ms",
        commit_time
    );
    info!(
        "   - Commitment size: {} bytes",
        commit_output.commitment.len()
    );
    info!(
        "   - Codeword length: {} elements",
        commit_output.codeword.len()
    );

    drop(_span);

    let _span = span!(Level::INFO, "codeword_encoding").entered();
    info!("🔄 Phase 5: Encoding codeword");
    let start = Instant::now();
    let encoded_codeword = friveil
        .encode_codeword(&packed_mle_values.packed_values, fri_params.clone(), &ntt)
        .unwrap();

    let encode_time = start.elapsed().as_millis();
    info!("✅ Codeword encoded in {} ms", encode_time);
    encoded_codeword
        .iter()
        .enumerate()
        .for_each(|(i, x)| assert_eq!(*x, commit_output.codeword[i]));
    drop(_span);

    let _span = span!(Level::INFO, "decode_codeword").entered();
    info!("🔄 Phase 6: Decoding codeword");
    let start = Instant::now();
    let decoded_codeword = friveil
        .decode_codeword(&encoded_codeword, fri_params.clone(), &ntt)
        .unwrap();
    let decode_time = start.elapsed().as_millis();
    info!("✅ Codeword decoded in {} ms", decode_time);

    assert_eq!(decoded_codeword, packed_mle_values.packed_values);
    drop(_span);

    // Test Reed-Solomon error correction by simulating data loss
    println!("\n=== ERROR CORRECTION TEST ===");
    println!("Simulating data loss and testing reconstruction...");

    // Create a corrupted version of the encoded codeword with some data points "lost"
    let mut corrupted_codeword = encoded_codeword.clone();
    let total_elements = corrupted_codeword.len();

    // Corrupt 40% of the points
    let corruption_percentage = 0.01;
    let corrupted_indices_vec = corrupt_codeword_randomly(
        &mut corrupted_codeword,
        corruption_percentage,
        Some(42u64), // Fixed seed for reproducible results
    );

    println!("Total codeword elements: {}", total_elements);
    println!(
        "Corrupted {} elements ({:.1}%)",
        corrupted_indices_vec.len(),
        corruption_percentage * 100.0
    );

    // Try to decode the corrupted codeword using proper error correction
    println!("\nAttempting to decode corrupted codeword with error correction...");
    let start = Instant::now();

    assert_ne!(corrupted_codeword, encoded_codeword);

    let _reconstructed_codeword = friveil
        .reconstruct_codeword_naive(&mut corrupted_codeword, &corrupted_indices_vec)
        .unwrap();

    let reconstruction_time = start.elapsed().as_millis();

    println!("Reconstruction completed in {} ms", reconstruction_time);
    assert_eq!(corrupted_codeword, encoded_codeword);
    let _span = span!(Level::INFO, "proof_generation").entered();
    info!("📝 Phase 6: Generating evaluation proof");
    let start = Instant::now();
    let mut verifier_transcript = friveil
        .prove(
            packed_mle_values.packed_mle.clone(),
            fri_params.clone(),
            &ntt,
            &commit_output,
            &evaluation_point,
        )
        .unwrap();
    let proof_time = start.elapsed().as_millis();

    info!("✅ Evaluation proof generated in {} ms", proof_time);

    drop(_span);

    let _span = span!(Level::INFO, "evaluation_claim").entered();

    info!("🧮 Computing evaluation claim");
    let start = Instant::now();
    let evaluation_claim = friveil
        .calculate_evaluation_claim(&packed_mle_values.packed_values, &evaluation_point)
        .unwrap();
    let claim_time = start.elapsed().as_millis();
    info!("✅ Evaluation claim computed in {} ms", claim_time);
    debug!("   - Evaluation claim value: {:?}", evaluation_claim);
    drop(_span);

    let _span = span!(Level::INFO, "final_verification").entered();
    info!("🔍 Phase 7: Final proof verification");

    // Extract transcript bytes for network propagation
    let transcript_bytes = friveil.get_transcript_bytes(&verifier_transcript);
    info!(
        "📦 Transcript size: {} bytes (ready for network transmission)",
        transcript_bytes.len()
    );

    // Example: On the receiving network node, you would do:
    // let mut reconstructed_transcript = reconstruct_transcript_from_bytes(transcript_bytes);
    // Then use it for verification:
    // friveil.verify_evaluation(&mut reconstructed_transcript, evaluation_claim, &evaluation_point, &fri_params)?;

    let start = Instant::now();
    let result = friveil.verify_evaluation(
        &mut verifier_transcript,
        evaluation_claim,
        &evaluation_point,
        &fri_params,
    );
    let verification_time = start.elapsed().as_millis();

    match &result {
        Ok(_) => {
            info!(
                "✅ Final verification succeeded in {} ms",
                verification_time
            );
            info!("🎉 Data Availability Sampling scheme completed successfully!");
        }
        Err(e) => {
            error!(
                "❌ Final verification failed in {} ms: {:?}",
                verification_time, e
            );
            error!("💥 Data Availability Sampling scheme failed!");
        }
    }
    drop(_span);

    // Summary
    info!("📊 === EXECUTION SUMMARY ===");
    info!("Final verification result: {:?}", result);
    info!("🏁 Binius Data Availability Sampling completed");
}

/// Corrupts a codeword by randomly setting specified percentage of elements to zero
///
/// # Arguments
/// * `codeword` - The codeword to corrupt (modified in place)
/// * `corruption_percentage` - Percentage of elements to corrupt (0.0 to 1.0)
/// * `seed` - Optional seed for reproducible results. If None, uses system randomness
///
/// # Returns
/// * `Vec<usize>` - Vector of indices that were corrupted
fn corrupt_codeword_randomly(
    codeword: &mut [B128],
    corruption_percentage: f64,
    seed: Option<u64>,
) -> Vec<usize> {
    let total_elements = codeword.len();
    let num_corrupted_points = (total_elements as f64 * corruption_percentage) as usize;

    if num_corrupted_points == 0 {
        return Vec::new();
    }

    // Create RNG with optional seed
    let mut rng = if let Some(seed) = seed {
        StdRng::seed_from_u64(seed)
    } else {
        // Use current time as seed for randomness
        StdRng::seed_from_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        )
    };

    // Use reservoir sampling to efficiently select random indices
    let corrupted_indices = sample(&mut rng, total_elements, num_corrupted_points).into_vec();

    // Corrupt the selected indices by setting them to zero
    for &index in &corrupted_indices {
        codeword[index] = B128::zero();
    }

    corrupted_indices
}
