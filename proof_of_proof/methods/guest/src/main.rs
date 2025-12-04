use proof_core::GuestInput;
use risc0_zkvm::guest::{self, env};
use std::io::Read;

use proof_core::GuestInputTuple;
use FRIVeil::{
    friveil::FriVeilDefault,
    traits::B128,
    traits::{FRIVeilSampling, FriVeilUtils},
};

const LOG_INV_RATE: usize = 1;
const NUM_TEST_QUERIES: usize = 128;

fn main() {
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    let (data, evaluation_point, evaluation_claim, packed_log_val): GuestInputTuple =
        bincode::deserialize(&input_bytes).unwrap();

    let friveil = FriVeilDefault::new(
        LOG_INV_RATE,
        NUM_TEST_QUERIES,
        14,
        80, // log_num_shares
    );

    // Initialize FRI context to get fri_params
    let (fri_params, _) = friveil
        .initialize_fri_context(packed_log_val)
        .expect("Failed to initialize FRI context");

    let evaluation_claim = B128::from(u128::from_le_bytes(evaluation_claim));
    let evaluation_point_vec = evaluation_point
        .iter()
        .map(|p| B128::from(u128::from_le_bytes(*p)))
        .collect::<Vec<_>>();

    // for proof in data.iter() {
    //     let mut verifier_transcript = friveil.reconstruct_transcript_from_bytes(proof.to_vec());

    //     let result = friveil.verify_evaluation(
    //         &mut verifier_transcript,
    //         evaluation_claim,
    //         &evaluation_point_vec,
    //         &fri_params,
    //     );

    //     // assert!(
    //     //     result.is_ok(),
    //     //     "FRI verification failed for proof {} {:?}",
    //     //     i,
    //     //     result
    //     // );
    // }

    // write public output to the journal
    env::commit(&true);
}
