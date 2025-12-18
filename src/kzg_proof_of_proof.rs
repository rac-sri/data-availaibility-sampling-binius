use kate::{
    M1NoPrecomp,
    gridgen::core::{AsBytes, EvaluationGrid},
};

pub use kate::couscous::multiproof_params;

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
