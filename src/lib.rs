#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(target_feature = "avx2")]
mod avx;

#[cfg(target_feature = "avx2")]
mod bits_find_lsb;

mod consts;
mod decode;
mod encode;
mod error;
pub use decode::{base58_decode_32, base58_decode_64};
pub use encode::{base58_encode_32, base58_encode_64};
pub use error::DecodeError;
mod unlikely;
