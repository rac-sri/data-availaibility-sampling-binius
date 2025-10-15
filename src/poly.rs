use binius_field::{ExtensionField, PackedField};
use binius_math::FieldBuffer;
use binius_verifier::config::B1;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::marker::PhantomData;
use tracing::debug;

const BYTES_PER_ELEMENT: usize = 16; // 128 bit = 16 bytes

pub struct FriVeilUtils<P> {
    log_scalar_bit_width: usize,
    _p: PhantomData<P>,
}

impl<P> FriVeilUtils<P>
where
    P: PackedField + ExtensionField<B1>,
    P::Scalar: From<u128> + ExtensionField<B1>,
{
    pub fn new() -> Self {
        Self {
            log_scalar_bit_width: <P::Scalar as ExtensionField<B1>>::LOG_DEGREE,
            _p: PhantomData,
        }
    }

    pub fn bytes_to_packed_mle(
        &self,
        data: &[u8],
    ) -> Result<(FieldBuffer<P>, Vec<P::Scalar>, usize), String> {
        let num_elements = data.len().div_ceil(BYTES_PER_ELEMENT);
        let padded_size = num_elements.next_power_of_two();

        let n_vars = padded_size.ilog2() as usize;
        debug!("N vars: {:?}", n_vars);
        let big_field_n_vars = n_vars - self.log_scalar_bit_width;
        let packed_size = 1 << big_field_n_vars;
        debug!("Packed size: {:?}", packed_size);

        #[cfg(feature = "parallel")]
        let mut packed_values: Vec<P::Scalar> = {
            data.par_chunks(BYTES_PER_ELEMENT)
                .map(|chunk| {
                    let mut bytes_array = [0u8; 16];
                    bytes_array[..chunk.len()].copy_from_slice(chunk);
                    P::Scalar::from(u128::from_le_bytes(bytes_array))
                })
                .collect()
        };

        #[cfg(not(feature = "parallel"))]
        let mut packed_values: Vec<P::Scalar> = {
            let mut values = Vec::with_capacity(num_elements);
            for chunk in data.chunks(BYTES_PER_ELEMENT) {
                let mut bytes_array = [0u8; 16];
                bytes_array[..chunk.len()].copy_from_slice(chunk);
                let scalar = P::Scalar::from(u128::from_le_bytes(bytes_array));
                values.push(scalar);
            }
            values
        };

        debug!("Packed values: {:?}", packed_values.len());
        packed_values.resize(packed_size, P::Scalar::zero());

        debug!("Packed values: {:?}", packed_values.len());

        let packed_mle =
            FieldBuffer::<P>::from_values(packed_values.as_slice()).map_err(|e| e.to_string())?;

        let big_field_n_vars = packed_mle.log_len();
        let total_n_vars = big_field_n_vars + self.log_scalar_bit_width;

        Ok((packed_mle, packed_values, total_n_vars))
    }
}
