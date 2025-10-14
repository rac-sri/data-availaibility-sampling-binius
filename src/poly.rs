use binius_field::{ExtensionField, PackedField};
use binius_math::FieldBuffer;
use binius_verifier::config::B1;

const BYTES_PER_ELEMENT: usize = 16; // 128 bit = 16 bytes

pub fn bytes_to_packed_mle<P: PackedField>(
    data: &[u8],
) -> Result<(FieldBuffer<P>, Vec<P::Scalar>, usize), String>
where
    P::Scalar: From<u128> + ExtensionField<B1>,
{
    let log_scalar_bit_width: usize = <P::Scalar as ExtensionField<B1>>::LOG_DEGREE;

    let num_elements = data.len().div_ceil(BYTES_PER_ELEMENT);
    let padded_size = num_elements.next_power_of_two();

    let packed_size = if padded_size >> log_scalar_bit_width == 0 {
        1
    } else {
        padded_size >> log_scalar_bit_width
    };

    let mut packed_values = Vec::<P::Scalar>::with_capacity(packed_size);

    for chunk in data.chunks(BYTES_PER_ELEMENT) {
        let mut bytes_array = [0u8; 16];
        bytes_array[..chunk.len()].copy_from_slice(chunk);
        let scalar = P::Scalar::from(u128::from_le_bytes(bytes_array));
        packed_values.push(scalar);
    }

    packed_values.resize(packed_size, P::Scalar::zero());
    let packed_mle =
        FieldBuffer::<P>::from_values(packed_values.as_slice()).map_err(|e| e.to_string())?;

    let big_field_n_vars = packed_mle.log_len();
    let total_n_vars = big_field_n_vars + log_scalar_bit_width;

    Ok((packed_mle, packed_values, total_n_vars))
}
