use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::fmt::Debug;

/// An error describing which elliptic curve call failed.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EccError {
	#[error("")]
	Bls12_377MultiMillerLoop,
	#[error("")]
	Bls12_377FinalExponentiation,
	#[error("")]
	Bls12_377G1Projective,
	#[error("")]
	Bls12_377G2Projective,
	#[error("")]
	Bls12_381G1Projective,
	#[error("")]
	Bls12_381G2Projective,
	#[error("")]
	Bls12_381MultiMillerLoop,
	#[error("")]
	Bls12_381FinalExponentiation,
	#[error("")]
	Bls12_381Groth16,
	#[error("")]
	Bw6_761G1Projective,
	#[error("")]
	Bw6_761G2Projective,
	#[error("")]
	Bw6_761MsmG1,
	#[error("")]
	Bw6_761MsmG2,
	#[error("")]
	Bw6_761MultiMillerLoop,
	#[error("")]
	Bw6_761FinalExponentiation,
	#[error("")]
	EdOnBls12_377MulProjective,
	#[error("")]
	EdOnBls12_377Msm,
	#[error("")]
	EdOnBls12_381BandersnatchSwMulProjective,
	#[error("")]
	EdOnBls12_381BandersnatchTeMulProjective,
	#[error("")]
	EdOnBls12_381BandersnatchSwMsm,
	#[error("")]
	EdOnBls12_381BandersnatchTeMsm,
	#[error("")]
	Bls12_381Groth16UnexpectedValidation,
}

#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Groth16Error {
	#[error("Failed to compute projective mul for g1 on bls12_381")]
	Groth16Verification,
}
