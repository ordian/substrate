use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::fmt::Debug;

/// An error describing which elliptic curve call failed.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EccError {
	// #[error("Failed to compute projective mul for g1 on bls12_381")]
	Bls12_377MultiMillerLoop,
	Bls12_377FinalExponentiation,
	Bls12_377G1Projective,
	Bls12_377G2Projective,
	Bls12_381G1Projective,
	Bls12_381G2Projective,
	Bls12_381MultiMillerLoop,
	Bls12_381FinalExponentiation,
	Bls12_381Groth16,
	Bw6_761G1Projective,
	Bw6_761G2Projective,
	Bw6_761MsmG1,
	Bw6_761MsmG2,
	Bw6_761MultiMillerLoop,
	Bw6_761FinalExponentiation,
	EdOnBls12_377MulProjective,
	EdOnBls12_377Msm,
	EdOnBls12_381BandersnatchSwMulProjective,
	EdOnBls12_381BandersnatchTeMulProjective,
	EdOnBls12_381BandersnatchSwMsm,
	EdOnBls12_381BandersnatchTeMsm,
	Bls12_381Groth16UnexpectedValidation,
}

#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Groth16Error {
	// #[error("Failed to compute projective mul for g1 on bls12_381")]
	Groth16Verification,
}
