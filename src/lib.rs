#[cfg(target_feature = "avx2")]
use std::arch::x86_64::{
    __m128i, _mm256_extractf128_si256, _mm256_maskstore_epi64, _mm_bslli_si128, _mm_storeu_si128,
};

#[cfg(target_feature = "avx2")]
mod avx;

#[cfg(target_feature = "avx2")]
use avx::{
    count_leading_zeros_32, count_leading_zeros_45, intermediate_to_raw, raw_to_base58,
    ten_per_slot_down_32, wl, wl_and, wl_bcast, wl_eq, wl_gt, wl_ld, wl_shl, wl_shru,
    wl_shru_vector, wuc_ldu,
};

const FD_BASE58_ENCODED_32_LEN: usize = 44; /* Computed as ceil(log_58(256^32 - 1)) */
const FD_BASE58_ENCODED_64_LEN: usize = 88; /* Computed as ceil(log_58(256^64 - 1)) */
const FD_BASE58_ENCODED_32_SZ: usize = FD_BASE58_ENCODED_32_LEN + 1; /* Including the nul terminator */
const FD_BASE58_ENCODED_64_SZ: usize = FD_BASE58_ENCODED_64_LEN + 1; /* Including the nul terminator */

#[cfg(not(target_feature = "avx2"))]
const BASE58_CHARS: [i8; 58] = [
    b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8, b'7' as i8, b'8' as i8,
    b'9' as i8, b'A' as i8, b'B' as i8, b'C' as i8, b'D' as i8, b'E' as i8, b'F' as i8, b'G' as i8,
    b'H' as i8, b'J' as i8, b'K' as i8, b'L' as i8, b'M' as i8, b'N' as i8, b'P' as i8, b'Q' as i8,
    b'R' as i8, b'S' as i8, b'T' as i8, b'U' as i8, b'V' as i8, b'W' as i8, b'X' as i8, b'Y' as i8,
    b'Z' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8, b'e' as i8, b'f' as i8, b'g' as i8,
    b'h' as i8, b'i' as i8, b'j' as i8, b'k' as i8, b'm' as i8, b'n' as i8, b'o' as i8, b'p' as i8,
    b'q' as i8, b'r' as i8, b's' as i8, b't' as i8, b'u' as i8, b'v' as i8, b'w' as i8, b'x' as i8,
    b'y' as i8, b'z' as i8,
];
const BASE58_INVALID_CHAR: u8 = 255;
const BASE58_INVERSE_TABLE_OFFSET: u8 = '1' as u8;
const BASE58_INVERSE_TABLE_SENTINEL: u8 = 1 + ('z' as u8) - BASE58_INVERSE_TABLE_OFFSET;

const BAD: u8 = BASE58_INVALID_CHAR;
const BASE58_INVERSE: [u8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, BAD, BAD, BAD, BAD, BAD, BAD, BAD, 9, 10, 11, 12, 13, 14, 15, 16,
    BAD, 17, 18, 19, 20, 21, BAD, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, BAD, BAD, BAD, BAD,
    BAD, BAD, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, BAD, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, BAD,
];

const N: usize = 32;
const BYTE_CNT: usize = N;
const INTERMEDIATE_SZ: usize = 9;
const RAW58_SZ: usize = INTERMEDIATE_SZ * 5;
const BINARY_SZ: usize = N / 4;

/* Contains the unique values less than 58^5 such that:
  2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k))

The second dimension of this table is actually ceil(log_(58^5)
(2^(32*(BINARY_SZ-1))), but that's almost always INTERMEDIATE_SZ-1 */

const ENC_TABLE_32: [[u32; INTERMEDIATE_SZ - 1]; BINARY_SZ] = [
    [
        513735, 77223048, 437087610, 300156666, 605448490, 214625350, 141436834, 379377856,
    ],
    [
        0, 78508, 646269101, 118408823, 91512303, 209184527, 413102373, 153715680,
    ],
    [
        0, 0, 11997, 486083817, 3737691, 294005210, 247894721, 289024608,
    ],
    [0, 0, 0, 1833, 324463681, 385795061, 551597588, 21339008],
    [0, 0, 0, 0, 280, 127692781, 389432875, 357132832],
    [0, 0, 0, 0, 0, 42, 537767569, 410450016],
    [0, 0, 0, 0, 0, 0, 6, 356826688],
    [0, 0, 0, 0, 0, 0, 0, 1],
];

/* Contains the unique values less than 2^32 such that:
58^(5*(8-j)) = sum_k table[j][k]*2^(32*(7-k)) */
const DEC_TABLE_32: [[u32; BINARY_SZ]; INTERMEDIATE_SZ] = [
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

#[inline(always)]
fn fd_uint_bswap(x: u32) -> u32 {
    x.to_be()
}

#[inline(always)]
fn fd_uint_load_4(p: *const u8) -> u32 {
    let mut t: u32 = 0;
    unsafe {
        // Unsafe block needed for dereferencing raw pointer
        let p_t = &mut t as *mut u32;
        let p_p = p as *const u32;
        std::ptr::copy_nonoverlapping(p_p, p_t, 1);
    }
    t
}

const fn fd_ulong_align_up(x: usize, a: usize) -> usize {
    ((x) + ((a) - 1)) & (!((a) - 1))
}

#[cfg(target_feature = "avx2")]
const INTERMEDIATE_SZ_W_PADDING: usize = fd_ulong_align_up(INTERMEDIATE_SZ, 4);

#[cfg(not(target_feature = "avx2"))]
const INTERMEDIATE_SZ_W_PADDING: usize = INTERMEDIATE_SZ;

#[inline(always)]
fn fd_ulong_store_if(c: bool, p: *mut u8, v: u8) {
    if c {
        unsafe { *p = v };
    }
}

#[cfg(target_feature = "avx2")]
#[repr(C, align(32))]
struct Intermediate([u64; INTERMEDIATE_SZ_W_PADDING]);

#[cfg(not(target_feature = "avx2"))]
#[repr(C)]
struct Intermediate([u64; INTERMEDIATE_SZ_W_PADDING]);

pub fn fd_base58_encode_32(bytes: *const u8, opt_len: *mut u8, out: *mut i8) -> *mut i8 {
    let in_leading_0s = {
        #[cfg(target_feature = "avx2")]
        {
            let bytes_ = wuc_ldu(bytes);
            count_leading_zeros_32(bytes_)
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            let mut in_leading_0s = 0;
            while in_leading_0s < BYTE_CNT {
                if unsafe { bytes.add(in_leading_0s as usize).read() != 0 } {
                    break;
                }
                in_leading_0s += 1;
            }
            in_leading_0s
        }
    };
    let mut binary = [0u32; BINARY_SZ];
    for i in 0..BINARY_SZ {
        binary[i] = fd_uint_bswap(fd_uint_load_4(unsafe {
            bytes.offset((i * std::mem::size_of::<u32>()) as isize)
        }));
    }
    let r1div = 656356768u64;
    /* Convert to the intermediate format:
      X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
    Initially, we don't require intermediate[i] < 58^5, but we do want
    to make sure the sums don't overflow. */
    let mut intermediate = Intermediate([0u64; INTERMEDIATE_SZ_W_PADDING]);
    for i in 0..BINARY_SZ {
        for j in 0..INTERMEDIATE_SZ - 1 {
            let multiplier = ENC_TABLE_32[i][j] as u64;
            intermediate.0[j + 1] += binary[i] as u64 * multiplier;
        }
    }
    /* Now we make sure each term is less than 58^5. Again, we have to be
    a bit careful of overflow.

    For N==32, in the worst case, as before, intermediate[8] will be
    just over 2^63 and intermediate[7] will be just over 2^62.6.  In
    the first step, we'll add floor(intermediate[8]/58^5) to
    intermediate[7].  58^5 is pretty big though, so intermediate[7]
    barely budges, and this is still fine.

    For N==64, in the worst case, the biggest entry in intermediate at
    this point is 2^63.87, and in the worst case, we add (2^64-1)/58^5,
    which is still about 2^63.87. */

    for i in (1..=INTERMEDIATE_SZ - 1).rev() {
        intermediate.0[i - 1] += intermediate.0[i] / r1div;
        intermediate.0[i] %= r1div;
    }
    let skip = {
        #[cfg(not(target_feature = "avx2"))]
        {
            /* Convert intermediate form to base 58.  This form of conversion
            exposes tons of ILP, but it's more than the CPU can take advantage
            of.
              X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
            let mut raw_base58 = [0u8; RAW58_SZ];
            for i in 0..INTERMEDIATE_SZ {
                /* We know intermediate[ i ] < 58^5 < 2^32 for all i, so casting to
                a uint is safe.  GCC doesn't seem to be able to realize this, so
                when it converts ulong/ulong to a magic multiplication, it
                generates the single-op 64b x 64b -> 128b mul instruction.  This
                hurts the CPU's ability to take advantage of the ILP here. */
                let v = intermediate.0[i] as u32;
                raw_base58[5 * i + 4] = ((v / 1) % 58) as u8;
                raw_base58[5 * i + 3] = ((v / 58) % 58) as u8;
                raw_base58[5 * i + 2] = ((v / 3364) % 58) as u8;
                raw_base58[5 * i + 1] = ((v / 195112) % 58) as u8;
                raw_base58[5 * i + 0] = (v / 11316496) as u8; /* We know this one is less than 58 */
            }
            /* Finally, actually convert to the string.  We have to ignore all the
            leading zeros in raw_base58 and instead insert in_leading_0s
            leading '1' characters.  We can show that raw_base58 actually has
            at least in_leading_0s, so we'll do this by skipping the first few
            leading zeros in raw_base58. */
            let mut raw_leading_0s = 0;
            while raw_leading_0s < RAW58_SZ {
                if raw_base58[raw_leading_0s] != 0 {
                    break;
                }
                raw_leading_0s += 1;
            }
            /* It's not immediately obvious that raw_leading_0s >= in_leading_0s,
            but it's true.  In base b, X has floor(log_b X)+1 digits.  That
            means in_leading_0s = N-1-floor(log_256 X) and raw_leading_0s =
            RAW58_SZ-1-floor(log_58 X).  Let X<256^N be given and consider:

            raw_leading_0s - in_leading_0s =
              =  RAW58_SZ-N + floor( log_256 X ) - floor( log_58 X )
              >= RAW58_SZ-N - 1 + ( log_256 X - log_58 X ) .

            log_256 X - log_58 X is monotonically decreasing for X>0, so it
            achieves it minimum at the maximum possible value for X, i.e.
            256^N-1.
              >= RAW58_SZ-N-1 + log_256(256^N-1) - log_58(256^N-1)

            When N==32, RAW58_SZ is 45, so this gives skip >= 0.29
            When N==64, RAW58_SZ is 90, so this gives skip >= 1.59.

            Regardless, raw_leading_0s - in_leading_0s >= 0. */
            let skip = raw_leading_0s - in_leading_0s;
            for i in 0..(RAW58_SZ - skip) {
                unsafe {
                    *out.offset(i as isize) = BASE58_CHARS[raw_base58[skip + i] as usize];
                }
            }
            skip
        }

        #[cfg(target_feature = "avx2")]
        {
            let intermediate_ptr = intermediate.0.as_ptr() as *const i64;
            let intermediate0 = wl_ld(intermediate_ptr);
            let intermediate1 = wl_ld(unsafe { intermediate_ptr.offset(4) });
            let intermediate2 = wl_ld(unsafe { intermediate_ptr.offset(8) });
            let raw0 = intermediate_to_raw(intermediate0);
            let raw1 = intermediate_to_raw(intermediate1);
            let raw2 = intermediate_to_raw(intermediate2);
            let (compact0, compact1) = ten_per_slot_down_32(raw0, raw1, raw2);
            let raw_leading_0s = count_leading_zeros_45(compact0, compact1);
            let base58_0 = raw_to_base58(compact0);
            let base58_1 = raw_to_base58(compact1);
            let skip = raw_leading_0s - in_leading_0s;
            /* We know the final string is between 32 and 44 characters, so skip
             has to be in [1, 13].

             Suppose base58_0 is [ a0 a1 a2 ... af | b0 b1 b2 ... bf ] and skip
             is 2.
             It would be nice if we had something like the 128-bit barrel shifts
             we used in ten_per_slot_down, but they require immediates.
             Instead, we'll shift each ulong right by (skip%8) bytes:

             [ a2 a3 .. a7 0 0 aa ab .. af 0 0 | b2 b3 .. b7 0 0 ba .. bf 0 0 ]
             and maskstore to write just 8 bytes, skipping the first
             floor(skip/8) ulongs, to a starting address of out-8*floor(skip/8).

                   out
                     V
                   [ a2 a3 a4 a5 a6 a7  0  0 -- -- ... ]

             Now we use another maskstore on the original base58_0, masking out
             the first floor(skip/8)+1 ulongs, and writing to out-skip:
                   out
                     V
             [ -- -- -- -- -- -- -- -- a8 a9 aa ab ... bd be bf ]

             Finally, we need to write the low 13 bytes from base58_1 and a '\0'
             terminator, starting at out-skip+32.  The easiest way to do this is
             actually to shift in 3 more bytes, write the full 16B and do it
             prior to the previous write:
                                                       out-skip+29
                                                        V
                                                      [ 0  0  0  c0 c1 c2 .. cc ]
            */
            let w_skip = wl_bcast(skip as i64);
            let mod8_mask = wl_bcast(7);
            let compare = wl(0, 1, 2, 3);
            let shift_qty = wl_shl::<3>(wl_and(w_skip, mod8_mask)); /* bytes->bits */
            let shifted = wl_shru_vector(base58_0, shift_qty);
            let skip_div8 = wl_shru::<3>(w_skip);
            let mask1 = wl_eq(skip_div8, compare);
            let out_offset = unsafe { out.offset(-8 * (skip as isize / 8)) } as *mut i64;
            unsafe { _mm256_maskstore_epi64(out_offset, mask1, shifted) };
            let last = unsafe { _mm_bslli_si128(_mm256_extractf128_si256(base58_1, 0), 3) };
            unsafe { _mm_storeu_si128(out.offset(29 - skip as isize) as *mut __m128i, last) };
            let mask2 = wl_gt(compare, skip_div8);
            unsafe {
                _mm256_maskstore_epi64(out.offset(-(skip as isize)) as *mut i64, mask2, base58_0)
            };
            skip
        }
    };
    unsafe {
        *out.add(RAW58_SZ - skip as usize) = '0' as i8;
    }
    fd_ulong_store_if(!opt_len.is_null(), opt_len, RAW58_SZ as u8 - skip as u8);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_32_to_string(bytes: &[u8; 32], len: &mut [u8; 1], buf: &mut [i8; 45]) -> String {
        let res = fd_base58_encode_32(bytes.as_ptr(), len.as_mut_ptr(), buf.as_mut_ptr());
        let as_slice = unsafe { std::slice::from_raw_parts(res, len[0] as usize) };
        let collected: String = as_slice.iter().map(|c| *c as u8 as char).collect();
        collected
    }

    #[test]
    fn test_base58_encode_32() {
        let mut buf = [0i8; FD_BASE58_ENCODED_32_SZ];
        let mut len = [0u8];
        let mut bytes = [0u8; 32];
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "11111111111111111111111111111111"
        );
        assert_eq!(len[0], 32);
        bytes[31] += 1;
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "11111111111111111111111111111112"
        );
        assert_eq!(len[0], 32);
        bytes[30] += 1;
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "1111111111111111111111111111115S"
        );
        assert_eq!(len[0], 32);
        let mut bytes = [255u8; 32];
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
        );
        assert_eq!(len[0], 44);
        bytes[31] -= 1;
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFF"
        );
        assert_eq!(len[0], 44);
        let bytes = [1u8; 32];
        assert_eq!(
            &encode_32_to_string(&bytes, &mut len, &mut buf),
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
        );
        assert_eq!(len[0], 43);
    }
}
