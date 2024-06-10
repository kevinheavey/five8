use five8::{decode_32, decode_64, DecodeError};
use proptest::prelude::*;

fn decode_and_return_32(s: &str) -> Result<[u8; 32], DecodeError> {
    let mut out = [0u8; 32];
    decode_32(s, &mut out)?;
    Ok(out)
}

fn decode_and_return_32_bs58(s: &str) -> bs58::decode::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    bs58::decode(s).into(&mut out)?;
    Ok(out)
}

fn map_decode_errors(five8_err: DecodeError, bs58_err: bs58::decode::Error) {
    match bs58_err {
        bs58::decode::Error::BufferTooSmall => {
            assert_eq!(five8_err, DecodeError::OutputTooLong);
        }
        bs58::decode::Error::InvalidCharacter { .. }
        | bs58::decode::Error::NonAsciiCharacter { .. } => {
            assert!(matches!(five8_err, DecodeError::InvalidChar(..)));
        }
        _ => {
            panic!("Unexpected bs58_err: {bs58_err:?}");
        }
    }
}

fn decode_and_return_64(s: &str) -> Result<[u8; 64], DecodeError> {
    let mut out = [0u8; 64];
    decode_64(s, &mut out)?;
    Ok(out)
}

// fn compare_decode_results()

proptest! {
    #[test]
    fn doesnt_crash(s in "\\PC*") {
        let mut out = [0u8; 32];
        let _ = decode_32(&s, &mut out);
        let mut out = [0u8; 64];
        let _ = decode_64(&s, &mut out);
    }
}
