use core::array::from_fn;

use crate::{
    consts::{
        BINARY_SZ_32, BINARY_SZ_64, INTERMEDIATE_SZ_32, INTERMEDIATE_SZ_64, N_32, N_64,
        RAW58_SZ_32, RAW58_SZ_64,
    },
    encode::u8s_to_u32s_swapped_32_outer,
    error::DecodeError,
    unlikely::unlikely,
};

const BASE58_INVERSE_TABLE_OFFSET: u8 = b'1';
const BASE58_INVERSE_TABLE_SENTINEL: u8 = 1 + b'z' - BASE58_INVERSE_TABLE_OFFSET;

const BASE58_INVALID_CHAR: u8 = 255;

const BAD: u8 = BASE58_INVALID_CHAR;
const BASE58_INVERSE: [u8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, BAD, BAD, BAD, BAD, BAD, BAD, BAD, 9, 10, 11, 12, 13, 14, 15, 16,
    BAD, 17, 18, 19, 20, 21, BAD, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, BAD, BAD, BAD, BAD,
    BAD, BAD, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, BAD, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, BAD,
];

#[inline]
pub(crate) fn base58_decode<
    const ENCODED_SZ: usize,
    const RAW58_SZ: usize,
    const INTERMEDIATE_SZ: usize,
    const BINARY_SZ: usize,
    const N: usize,
>(
    encoded: &[u8],
    out: &mut [u8; N],
    dec_table: &[[u32; BINARY_SZ]; INTERMEDIATE_SZ],
) -> Result<(), DecodeError> {
    let binary = base58_decode_before_be_convert::<ENCODED_SZ, RAW58_SZ, INTERMEDIATE_SZ, BINARY_SZ>(
        encoded, dec_table,
    )?;
    let binary_u8 = binary.as_ptr() as *const u8;
    /* Convert each term to big endian for the final output */
    for i in 0..BINARY_SZ {
        // take the first four bytes of each 8-byte block and reverse them:
        // 3 2 1 0 11 10 9 8 19 18 17 16 27 26 25 24 etc
        // or if on a BE machine, just take the last four bytes of each 8-byte block:
        // 4 5 6 7 12 13 14 15 20 21 22 23 etc
        let binary_u8_idx = i * 8;
        let out_idx = i * 4;
        #[cfg(target_endian = "little")]
        unsafe {
            *out.get_unchecked_mut(out_idx) = *binary_u8.add(binary_u8_idx + 3);
            *out.get_unchecked_mut(out_idx + 1) = *binary_u8.add(binary_u8_idx + 2);
            *out.get_unchecked_mut(out_idx + 2) = *binary_u8.add(binary_u8_idx + 1);
            *out.get_unchecked_mut(out_idx + 3) = *binary_u8.add(binary_u8_idx);
        }
        #[cfg(target_endian = "big")]
        unsafe {
            *out.get_unchecked_mut(out_idx) = *binary_u8.add(binary_u8_idx + 4);
            *out.get_unchecked_mut(out_idx + 1) = *binary_u8.add(binary_u8_idx + 5);
            *out.get_unchecked_mut(out_idx + 2) = *binary_u8.add(binary_u8_idx + 6);
            *out.get_unchecked_mut(out_idx + 3) = *binary_u8.add(binary_u8_idx + 7);
        }
    }
    base58_decode_after_be_convert(out, encoded)
}

// #[inline]
// pub(crate) fn base58_decode_32_2(
//     encoded: &[u8],
//     out: &mut [u8; N_32],
// ) -> Result<(), DecodeError> {
//     let binary = base58_decode_before_be_convert::<BASE58_ENCODED_32_SZ, RAW58_SZ_32, INTERMEDIATE_SZ_32, BINARY_SZ_32>(
//         encoded, &DEC_TABLE_32,
//     )?;
//     let binary_u8 = binary.as_ptr() as *const u8;
//     /* Convert each term to big endian for the final output */
//     u8s_to_u32s_swapped_32_outer(out, &binary);
//     base58_decode_after_be_convert(out, encoded)
// }

fn base58_decode_after_be_convert<const N: usize>(
    out: &mut [u8; N],
    encoded: &[u8],
) -> Result<(), DecodeError> {
    /* Make sure the encoded version has the same number of leading '1's
    as the decoded version has leading 0s. The check doesn't read past
    the end of encoded, because '\0' != '1', so it will return NULL. */
    let mut leading_zero_cnt = 0u64;
    while leading_zero_cnt < N as u64 {
        let out_val = unsafe { *out.get_unchecked(leading_zero_cnt as usize) };
        if out_val != 0 {
            break;
        }
        if unlikely(unsafe { *encoded.get_unchecked(leading_zero_cnt as usize) != b'1' }) {
            return Err(DecodeError::WhatToCallThis);
        }
        leading_zero_cnt += 1;
    }
    if unlikely(unsafe { *encoded.get_unchecked(leading_zero_cnt as usize) == b'1' }) {
        return Err(DecodeError::WhatToCallThisToo);
    }
    Ok(())
}

#[inline(always)]
fn base58_decode_before_be_convert<
    const ENCODED_SZ: usize,
    const RAW58_SZ: usize,
    const INTERMEDIATE_SZ: usize,
    const BINARY_SZ: usize,
>(
    encoded: &[u8],
    dec_table: &[[u32; BINARY_SZ]; INTERMEDIATE_SZ],
) -> Result<[u64; BINARY_SZ], DecodeError> {
    let mut char_cnt = 0usize;
    while char_cnt < ENCODED_SZ {
        let c = unsafe { *encoded.get_unchecked(char_cnt) };
        if c == 0 {
            break;
        }
        /* If c<'1', this will underflow and idx will be huge */
        let idx = (c as u64).wrapping_sub(BASE58_INVERSE_TABLE_OFFSET as u64);
        let idx = idx.min(BASE58_INVERSE_TABLE_SENTINEL as u64);
        char_cnt += 1;
        if unlikely(unsafe { *BASE58_INVERSE.get_unchecked(idx as usize) } == BASE58_INVALID_CHAR) {
            return Err(DecodeError::InvalidChar(c));
        }
    }
    if unlikely(char_cnt == ENCODED_SZ) {
        /* too long */
        return Err(DecodeError::TooLong);
    }
    let prepend_0 = RAW58_SZ - char_cnt;
    let raw_base58: [u8; RAW58_SZ] = from_fn(|j| {
        if j < prepend_0 {
            0
        } else {
            BASE58_INVERSE[(unsafe { *encoded.get_unchecked(j - prepend_0) }
                - BASE58_INVERSE_TABLE_OFFSET) as usize]
        }
    });
    let intermediate: [u64; INTERMEDIATE_SZ] = from_fn(|i| unsafe {
        *raw_base58.get_unchecked(5 * i) as u64 * 11316496
            + *raw_base58.get_unchecked(5 * i + 1) as u64 * 195112
            + *raw_base58.get_unchecked(5 * i + 2) as u64 * 3364
            + *raw_base58.get_unchecked(5 * i + 3) as u64 * 58
            + *raw_base58.get_unchecked(5 * i + 4) as u64
    });
    let mut binary: [u64; BINARY_SZ] = from_fn(|j| {
        let mut acc = 0u64;
        for i in 0..INTERMEDIATE_SZ {
            acc += unsafe {
                intermediate.get_unchecked(i) * *dec_table.get_unchecked(i).get_unchecked(j) as u64
            };
        }
        acc
    });
    for i in (1..BINARY_SZ).rev() {
        unsafe {
            *binary.get_unchecked_mut(i - 1) += binary.get_unchecked(i) >> 32;
        }
        unsafe {
            *binary.get_unchecked_mut(i) &= 0xFFFFFFFF;
        }
    }
    if unlikely(unsafe { *binary.get_unchecked(0) } > 0xFFFFFFFF) {
        return Err(DecodeError::LargestTermTooHigh);
    }
    Ok(binary)
}

/* Contains the unique values less than 2^32 such that:
58^(5*(8-j)) = sum_k table[j][k]*2^(32*(7-k)) */
const DEC_TABLE_32: [[u32; BINARY_SZ_32]; INTERMEDIATE_SZ_32] = [
    [
        1277, 2650397687, 3801011509, 2074386530, 3248244966, 687255411, 2959155456, 0,
    ],
    [
        0, 8360, 1184754854, 3047609191, 3418394749, 132556120, 1199103528, 0,
    ],
    [
        0, 0, 54706, 2996985344, 1834629191, 3964963911, 485140318, 1073741824,
    ],
    [
        0, 0, 0, 357981, 1476998812, 3337178590, 1483338760, 4194304000,
    ],
    [0, 0, 0, 0, 2342503, 3052466824, 2595180627, 17825792],
    [0, 0, 0, 0, 0, 15328518, 1933902296, 4063920128],
    [0, 0, 0, 0, 0, 0, 100304420, 3355157504],
    [0, 0, 0, 0, 0, 0, 0, 656356768],
    [0, 0, 0, 0, 0, 0, 0, 1],
];

const DEC_TABLE_64: [[u32; BINARY_SZ_64]; INTERMEDIATE_SZ_64] = [
    [
        249448, 3719864065, 173911550, 4021557284, 3115810883, 2498525019, 1035889824, 627529458,
        3840888383, 3728167192, 2901437456, 3863405776, 1540739182, 1570766848, 0, 0,
    ],
    [
        0, 1632305, 1882780341, 4128706713, 1023671068, 2618421812, 2005415586, 1062993857,
        3577221846, 3960476767, 1695615427, 2597060712, 669472826, 104923136, 0, 0,
    ],
    [
        0, 0, 10681231, 1422956801, 2406345166, 4058671871, 2143913881, 4169135587, 2414104418,
        2549553452, 997594232, 713340517, 2290070198, 1103833088, 0, 0,
    ],
    [
        0, 0, 0, 69894212, 1038812943, 1785020643, 1285619000, 2301468615, 3492037905, 314610629,
        2761740102, 3410618104, 1699516363, 910779968, 0, 0,
    ],
    [
        0, 0, 0, 0, 457363084, 927569770, 3976106370, 1389513021, 2107865525, 3716679421,
        1828091393, 2088408376, 439156799, 2579227194, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 2992822783, 383623235, 3862831115, 112778334, 339767049, 1447250220,
        486575164, 3495303162, 2209946163, 268435456, 0,
    ],
    [
        0, 0, 0, 0, 0, 4, 2404108010, 2962826229, 3998086794, 1893006839, 2266258239, 1429430446,
        307953032, 2361423716, 176160768, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 29, 3596590989, 3044036677, 1332209423, 1014420882, 868688145,
        4264082837, 3688771808, 2485387264, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 195, 1054003707, 3711696540, 582574436, 3549229270, 1088536814,
        2338440092, 1468637184, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 1277, 2650397687, 3801011509, 2074386530, 3248244966, 687255411,
        2959155456, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 8360, 1184754854, 3047609191, 3418394749, 132556120, 1199103528,
        0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54706, 2996985344, 1834629191, 3964963911, 485140318,
        1073741824,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 357981, 1476998812, 3337178590, 1483338760, 4194304000,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2342503, 3052466824, 2595180627, 17825792,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15328518, 1933902296, 4063920128,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100304420, 3355157504,
    ],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 656356768],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
];

const BASE58_ENCODED_32_LEN: usize = 44; /* Computed as ceil(log_58(256^32 - 1)) */
const BASE58_ENCODED_64_LEN: usize = 88; /* Computed as ceil(log_58(256^64 - 1)) */
pub(crate) const BASE58_ENCODED_32_SZ: usize = BASE58_ENCODED_32_LEN + 1; /* Including the nul terminator */
pub(crate) const BASE58_ENCODED_64_SZ: usize = BASE58_ENCODED_64_LEN + 1; /* Including the nul terminator */

#[inline]
pub fn base58_decode_32(encoded: &[u8], out: &mut [u8; N_32]) -> Result<(), DecodeError> {
    base58_decode::<BASE58_ENCODED_32_SZ, RAW58_SZ_32, INTERMEDIATE_SZ_32, BINARY_SZ_32, N_32>(
        encoded,
        out,
        &DEC_TABLE_32,
    )
}

#[inline]
pub fn base58_decode_64(encoded: &[u8], out: &mut [u8; N_64]) -> Result<(), DecodeError> {
    base58_decode::<BASE58_ENCODED_64_SZ, RAW58_SZ_64, INTERMEDIATE_SZ_64, BINARY_SZ_64, N_64>(
        encoded,
        out,
        &DEC_TABLE_64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_bad_decode_32(expected_err: DecodeError, encoded: &str) {
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let mut decoded = [0u8; 32];
        let err = base58_decode_32(&null_terminated, &mut decoded).unwrap_err();
        assert_eq!(err, expected_err);
    }

    fn check_bad_decode_64(expected_err: DecodeError, encoded: &str) {
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let mut decoded = [0u8; 64];
        let err = base58_decode_64(&null_terminated, &mut decoded).unwrap_err();
        assert_eq!(err, expected_err);
    }

    #[test]
    fn test_decode_error_32() {
        check_bad_decode_32(DecodeError::WhatToCallThis, "1");
        check_bad_decode_32(
            DecodeError::WhatToCallThis,
            "1111111111111111111111111111111",
        );
        check_bad_decode_32(
            DecodeError::WhatToCallThis,
            "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJz",
        );
        check_bad_decode_32(
            DecodeError::WhatToCallThis,
            "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL",
        );
        check_bad_decode_32(
            DecodeError::TooLong,
            "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4",
        );
        check_bad_decode_32(
            DecodeError::WhatToCallThisToo,
            "111111111111111111111111111111111",
        );
        check_bad_decode_32(
            DecodeError::LargestTermTooHigh,
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFJ",
        ); /* 2nd-smallest 33 byte value that doesn't start with 0x0 */
        check_bad_decode_32(
            DecodeError::WhatToCallThisToo,
            "11aEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWx",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(48),
            "11111111111111111111111111111110",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(33),
            "1111111111111111111111111111111!",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(73),
            "1111111111111111111111111111111I",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(79),
            "1111111111111111111111111111111O",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(95),
            "1111111111111111111111111111111_",
        );
        check_bad_decode_32(
            DecodeError::InvalidChar(108),
            "1111111111111111111111111111111l",
        );
    }

    #[test]
    fn test_decode_error_64() {
        check_bad_decode_64(DecodeError::WhatToCallThis, "1");
        check_bad_decode_64(
            DecodeError::WhatToCallThis,
            "111111111111111111111111111111111111111111111111111111111111111",
        );
        check_bad_decode_64(
            DecodeError::WhatToCallThis,
            "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA",
        );
        check_bad_decode_64(DecodeError::WhatToCallThis, "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QW");
        check_bad_decode_64(DecodeError::TooLong, "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QWabc");
        check_bad_decode_64(
            DecodeError::WhatToCallThisToo,
            "11111111111111111111111111111111111111111111111111111111111111111",
        );
        check_bad_decode_64(
            DecodeError::LargestTermTooHigh,
            "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roS"
        ); /* 2nd-smallest 65 byte value that doesn't start with 0x0 */

        check_bad_decode_64(DecodeError::WhatToCallThisToo, "1114tjGcyzrfXw2deDmDAFFaFyss32WRgkYdDJuprrNEL8kc799TrHSQHfE9fv6ZDBUg2dsMJdfYr71hjE4EfjEN"); /* Start with too many '1's */
        check_bad_decode_64(
            DecodeError::InvalidChar(48),
            "1111111111111111111111111111111111111111111111111111111111111110",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(33),
            "111111111111111111111111111111111111111111111111111111111111111!",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(59),
            "111111111111111111111111111111111111111111111111111111111111111;",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(73),
            "111111111111111111111111111111111111111111111111111111111111111I;",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(79),
            "111111111111111111111111111111111111111111111111111111111111111O",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(95),
            "111111111111111111111111111111111111111111111111111111111111111_",
        );
        check_bad_decode_64(
            DecodeError::InvalidChar(108),
            "111111111111111111111111111111111111111111111111111111111111111l",
        );
    }
}
