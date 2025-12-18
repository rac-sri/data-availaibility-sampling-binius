use binius_das_poc::{friveil::FriVeilDefault, poly::Utils};
use divan::Bencher;
use kate::{
    M1NoPrecomp,
    couscous::multiproof_params,
    gridgen::core::{AsBytes, EvaluationGrid},
};
use rand::Rng;
use std::u16;

fn main() {
    divan::main();
}

// A simple opinionated function to build KZG commitments over the data
#[cfg(feature = "kzg")]
pub fn kzg_commitment(data: &[u8], with_redundancy: bool, srs: &M1NoPrecomp) -> Vec<u8> {
    let max_width = srs.powers_of_g1.len();
    let max_height = u16::MAX as usize;

    let eval_grid = EvaluationGrid::from_data(data, 4, max_width, max_height, Default::default())
        .expect("valid evaluation grid");
    let poly_grid = eval_grid
        .into_polynomial_grid()
        .expect("valid polynomial grid");
    let commitments = if with_redundancy {
        poly_grid
            .extended_commitments(srs, 2)
            .expect("kzg commitments")
    } else {
        poly_grid.commitments(srs).expect("kzg commitments")
    };

    // Serialize commitments
    let mut commitment_bytes = Vec::with_capacity(commitments.len() * 48);
    for c in commitments {
        commitment_bytes.extend_from_slice(&c.to_bytes().unwrap());
    }

    commitment_bytes
}

#[cfg(feature = "kzg")]
#[divan::bench(max_time = 10)]
fn kzg_16mb_with_redundancy(bencher: Bencher) {
    let srs = multiproof_params();
    let real_data = std::fs::read("benches/16MB").unwrap();

    bencher.bench_local(|| {
        let _ = kzg_commitment(&real_data, true, &srs);
    });
}

#[cfg(feature = "kzg")]
#[divan::bench(max_time = 10)]
fn kzg_16mb_without_redundancy(bencher: Bencher) {
    let srs = multiproof_params();
    let real_data = std::fs::read("benches/16MB").unwrap();

    bencher.bench_local(|| {
        let _ = kzg_commitment(&real_data, false, &srs);
    });
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
