use scale_info::TypeInfo;
use sp_runtime::{
	codec::{Decode, Encode},
	RuntimeDebug,
};

/// An error describing which elliptic curve call failed.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EccError {
	// #[error("Failed to compute projective mul for g1 on bls12_381")]
	Bls12_381G1Projective,
}

// impl sp_blockchain::Error for EccError {}
