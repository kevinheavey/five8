#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoded = [0u8; 64];
    match five8::decode_64(&data, &mut decoded) {
        Ok(_) => {
            let b = bs58::decode(&data)
                .into_vec()
                .expect("Failed to decode base58 that five8 decoded");
            assert_eq!(&decoded.to_vec(), &b);

            let mut buf = [0u8; 88];
            let len = five8::encode_64(&decoded, &mut buf);
            assert_eq!(&buf[..len as usize], data);
            assert_eq!(data, bs58::encode(decoded).into_vec());
        }
        Err(five8::DecodeError::TooShort) => {
            if let Ok(b) = bs58::decode(&data).into_vec() {
                assert!(b.len() < 64);
            }
        }
        Err(five8::DecodeError::OutputTooLong)
        | Err(five8::DecodeError::LargestTermTooHigh)
        | Err(five8::DecodeError::TooLong) => {
            if let Ok(b) = bs58::decode(&data).into_vec() {
                assert!(b.len() > 64);
            }
        }
        Err(five8::DecodeError::InvalidChar(_)) => {
            let _ = bs58::decode(&data).into_vec().unwrap_err();
        }
    }

    let mut decoded = [0u8; 32];
    match five8::decode_32(&data, &mut decoded) {
        Ok(_) => {
            let b = bs58::decode(&data)
                .into_vec()
                .expect("Failed to decode base58 that five8 decoded");
            assert_eq!(&decoded.to_vec(), &b);

            let mut buf = [0u8; 44];
            let len = five8::encode_32(&decoded, &mut buf);
            assert_eq!(&buf[..len as usize], data);
            assert_eq!(data, bs58::encode(decoded).into_vec());
        }
        Err(five8::DecodeError::TooShort) => {
            if let Ok(b) = bs58::decode(&data).into_vec() {
                assert!(b.len() < 32);
            }
        }
        Err(five8::DecodeError::OutputTooLong)
        | Err(five8::DecodeError::LargestTermTooHigh)
        | Err(five8::DecodeError::TooLong) => {
            if let Ok(b) = bs58::decode(&data).into_vec() {
                assert!(b.len() > 32);
            }
        }
        Err(five8::DecodeError::InvalidChar(_)) => {
            let _ = bs58::decode(&data).into_vec().unwrap_err();
        }
    }
});
