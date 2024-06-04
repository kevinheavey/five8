#[derive(Debug, PartialEq)]
pub enum DecodeError {
    InvalidChar(u8),
    TooLong,
    TooShort,
    LargestTermTooHigh,
    WhatToCallThisToo,
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[cfg(feature = "std")]
impl core::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::InvalidChar(c) => {
                ::core::write!(formatter, "Illegal base58 char number: {}", c)
            }
            DecodeError::TooLong {} => formatter.write_str("Base58 string too long"),
            DecodeError::TooShort {} => formatter.write_str("Base58 string too short"),
            DecodeError::LargestTermTooHigh {} => {
                formatter.write_str("Largest term greater than 2^32")
            }
            DecodeError::WhatToCallThisToo {} => formatter.write_str("What to call this too"),
        }
    }
}
