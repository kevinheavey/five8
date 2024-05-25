#![no_main]

use bs58::decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data_len = data.len();
    if data_len >= 32 && data_len <= 44 && !data.contains(&b'\0') {
        if let Ok(s) = std::str::from_utf8(data) {
            let mut out = [0u8; 32];
            let mut fd_data = data.to_vec();
            fd_data.push(b'\0');
            let fd = five8::decode_32(&fd_data, &mut out);
            let decoded = decode(s).into_vec();

            if fd.is_err() && !decoded.is_err() {
                let bytes = decoded.unwrap();
                if bytes.len() == 32 {
                    // other library can decode things that aren't 32 bytes
                    panic!("five8 errored when bs58 was ok: {:?}, {:?}", bytes, fd);
                }
            } else if decoded.is_err() && !fd.is_err() {
                panic!("bs58 errored when five8 was ok: {:?}, {:?}", decoded, out);
            } else if decoded.is_err() && fd.is_err() {
                // good
            } else {
                let decoded_result = decoded.unwrap();
                if decoded_result.as_slice() != &out {
                    panic!(
                        "decode_32 gave different result: {:?}, {:?}",
                        decoded_result.as_slice(),
                        out
                    );
                }
            }
        }
    }
});
