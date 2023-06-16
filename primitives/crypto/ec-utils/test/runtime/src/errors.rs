use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::fmt::Debug;

/// An error describing which elliptic curve call failed.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EccError {
	// #[error("Failed to compute projective mul for g1 on bls12_381")]
	Bls12_381G1Projective,
}
