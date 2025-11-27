use FRIVeil::friveil::B128;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    pub data: Vec<Vec<u8>>,
    #[serde(with = "b128_vec_serde")]
    pub evaluation_point: Vec<B128>,
    #[serde(with = "b128_serde")]
    pub evaluation_claim: B128,
    pub packed_values_log_len: usize,
}

mod b128_serde {
    use FRIVeil::friveil::B128;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &B128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let u128_val: u128 = (*value).into();
        u128_val.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<B128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let u128_val = u128::deserialize(deserializer)?;
        Ok(B128::from(u128_val))
    }
}

mod b128_vec_serde {
    use FRIVeil::friveil::B128;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &Vec<B128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let u128_values: Vec<u128> = values.iter().map(|v| (*v).into()).collect();
        u128_values.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<B128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let u128_values = Vec::<u128>::deserialize(deserializer)?;
        Ok(u128_values.into_iter().map(B128::from).collect())
    }
}
