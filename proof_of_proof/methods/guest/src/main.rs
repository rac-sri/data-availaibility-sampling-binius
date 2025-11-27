use core::GuestInput;
use risc0_zkvm::guest::env;

use FRIVeil::{
    friveil::FriVeilDefault,
    traits::{FRIVeilSampling, FriVeilUtils},
};

const LOG_INV_RATE: usize = 1;
const NUM_TEST_QUERIES: usize = 2;

fn main() {
    // read the input
    let guest_input: GuestInput = env::read();

    let friveil = FriVeilDefault::new(
        LOG_INV_RATE,
        NUM_TEST_QUERIES,
        26,
        80, // log_num_shares
    );

    // Initialize FRI context to get fri_params
    let (fri_params, _) = friveil
        .initialize_fri_context(guest_input.packed_values_log_len)
        .expect("Failed to initialize FRI context");

    for (i, proof) in guest_input.data.iter().enumerate() {
        let mut verifier_transcript = friveil.reconstruct_transcript_from_bytes(proof.to_vec());
        let result = friveil.verify_evaluation(
            &mut verifier_transcript,
            guest_input.evaluation_claim,
            &guest_input.evaluation_point,
            &fri_params,
        );
        println!("{}: {:?}", i, result);
    }

    // TODO: do something with the input

    // write public output to the journal
    env::commit(&guest_input);
}
