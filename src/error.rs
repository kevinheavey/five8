#[derive(Debug, PartialEq)]
pub enum DecodeError {
    InvalidChar(u8),
    TooLong,
    TooShort,
    LargestTermTooHigh,
    OutputTooLong,
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
            DecodeError::TooLong => formatter.write_str("Base58 string too long"),
            DecodeError::TooShort => formatter.write_str("Base58 string too short"),
            DecodeError::LargestTermTooHigh => {
                formatter.write_str("Largest term greater than 2^32")
            }
            DecodeError::OutputTooLong => formatter.write_str("Decoded output has too many bytes"),
        }
    }
}

impl DecodeError {
    pub const fn unwrap_const(self) -> ! {
        match self {
            DecodeError::InvalidChar(_) => panic!("Illegal base58 char"),
            DecodeError::TooLong => panic!("Base58 string too long"),
            DecodeError::TooShort => panic!("Base58 string too short"),
            DecodeError::LargestTermTooHigh => panic!("Largest term greater than 2^32"),
            DecodeError::OutputTooLong => panic!("Decoded output has too many bytes"),
        }
    }
}
