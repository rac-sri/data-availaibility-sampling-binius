use binius_das_poc::{friveil::FriVeilDefault, poly::Utils};
use divan::Bencher;
use rand::Rng;

fn main() {
    divan::main();
}

const DATA_32_MIB: usize = 32 * 1024 * 1024;

#[divan::bench(max_time = 10)]
fn build_commitments_32mib_redundancy_factor_2(bencher: Bencher) {
    let mut rng = rand::rng();
    let random_data: Vec<u8> = (0..DATA_32_MIB).map(|_| rng.random()).collect();

    bencher.bench_local(|| {
        let packed_mle_values = Utils::new()
            .bytes_to_packed_mle(&random_data)
            .expect("Data should be convertible to packed MLE values");
        let friveil = FriVeilDefault::new(1, 100, packed_mle_values.total_n_vars, 3);
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.log_len())
            .expect("FRI context should initialize successfully");
        let _ = friveil
            .commit(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
            )
            .expect("Commitment should be created successfully");
    });
}

#[divan::bench(max_time = 10)]
fn build_commitments_32mib_redundancy_factor_4(bencher: Bencher) {
    let mut rng = rand::rng();
    let random_data: Vec<u8> = (0..DATA_32_MIB).map(|_| rng.random()).collect();

    bencher.bench_local(|| {
        let packed_mle_values = Utils::new()
            .bytes_to_packed_mle(&random_data)
            .expect("Data should be convertible to packed MLE values");
        let friveil = FriVeilDefault::new(2, 100, packed_mle_values.total_n_vars, 3);
        let (fri_params, ntt) = friveil
            .initialize_fri_context(packed_mle_values.packed_mle.log_len())
            .expect("FRI context should initialize successfully");
        let _ = friveil
            .commit(
                packed_mle_values.packed_mle.clone(),
                fri_params.clone(),
                &ntt,
            )
            .expect("Commitment should be created successfully");
    });
}
