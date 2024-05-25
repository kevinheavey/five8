#![no_main]

use bs58::encode;
use libfuzzer_sys::fuzz_target;

fn encode_32_to_string(
    bytes: &[u8; 32],
    len: &mut u8,
    buf: &mut [u8; 45],
) -> String {
    five8::encode_32(bytes, Some(len), buf);
    buf[..*len as usize].iter().map(|c| *c as char).collect()
}

fuzz_target!(|data: [u8; 32]| {
    let correct = encode(data.clone()).into_string();
    let mut encoded_buf = [0u8; 45];
    let mut decoded = [0u8; 32];
    let mut len = 0;
    let encoded = encode_32_to_string(&data, &mut len, &mut encoded_buf);
    five8::decode_32(&encoded_buf, &mut decoded).unwrap();

    // check encoding matches
    if correct != encoded {
        panic!("encode_32 fuzz encoding failed: {:?}, {:?}", correct, encoded);
    }

    // check round trip
    if decoded != data {
        panic!("encode_32 round trip failed: {:?}, {:?}", data, decoded);
    }
});
