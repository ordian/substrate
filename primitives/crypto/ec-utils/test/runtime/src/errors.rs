use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::fmt::Debug;

/// Groth16 verification errors
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Groth16Error {
	// #[error("Failed to compute projective mul for g1 on bls12_381")]
	Groth16Verification,
}
