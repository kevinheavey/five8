#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(target_feature = "avx2")]
use core::arch::x86_64::{
    __m128i, _mm256_extractf128_si256, _mm256_maskstore_epi64, _mm_bslli_si128, _mm_storeu_si128,
};

#[cfg(target_feature = "avx2")]
mod avx;

#[cfg(target_feature = "avx2")]
use avx::{
    count_leading_zeros_26, count_leading_zeros_32, count_leading_zeros_45, count_leading_zeros_64,
    intermediate_to_raw, raw_to_base58, ten_per_slot_down_32, ten_per_slot_down_64, wl, wl_and,
    wl_bcast, wl_eq, wl_gt, wl_ld, wl_shl, wl_shru, wl_shru_vector, wuc_ldu, wuc_stu,
};

#[cfg(target_feature = "avx2")]
mod bits_find_lsb;

const BASE58_ENCODED_32_LEN: usize = 44; /* Computed as ceil(log_58(256^32 - 1)) */
const BASE58_ENCODED_64_LEN: usize = 88; /* Computed as ceil(log_58(256^64 - 1)) */
const BASE58_ENCODED_32_SZ: usize = BASE58_ENCODED_32_LEN + 1; /* Including the nul terminator */
const BASE58_ENCODED_64_SZ: usize = BASE58_ENCODED_64_LEN + 1; /* Including the nul terminator */

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
const BASE58_INVERSE_TABLE_OFFSET: u8 = b'1';
const BASE58_INVERSE_TABLE_SENTINEL: u8 = 1 + b'z' - BASE58_INVERSE_TABLE_OFFSET;

const BAD: u8 = BASE58_INVALID_CHAR;
const BASE58_INVERSE: [u8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, BAD, BAD, BAD, BAD, BAD, BAD, BAD, 9, 10, 11, 12, 13, 14, 15, 16,
    BAD, 17, 18, 19, 20, 21, BAD, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, BAD, BAD, BAD, BAD,
    BAD, BAD, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, BAD, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, BAD,
];

const N_32: usize = 32;
const N_64: usize = 64;
const INTERMEDIATE_SZ_32: usize = 9; /* Computed by ceil(log_(58^5) (256^32-1)) */
const INTERMEDIATE_SZ_64: usize = 18; /* Computed by ceil(log_(58^5) (256^64-1)) */
const RAW58_SZ_32: usize = INTERMEDIATE_SZ_32 * 5;
const RAW58_SZ_64: usize = INTERMEDIATE_SZ_64 * 5;
const BINARY_SZ_32: usize = N_32 / 4;
const BINARY_SZ_64: usize = N_64 / 4;
const R1DIV: u64 = 656356768u64;

/* Contains the unique values less than 58^5 such that:
  2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k))

The second dimension of this table is actually ceil(log_(58^5)
(2^(32*(BINARY_SZ-1))), but that's almost always INTERMEDIATE_SZ-1 */

const ENC_TABLE_32: [[u32; INTERMEDIATE_SZ_32 - 1]; BINARY_SZ_32] = [
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

const ENC_TABLE_64: [[u32; INTERMEDIATE_SZ_64 - 1]; BINARY_SZ_64] = [
    [
        2631, 149457141, 577092685, 632289089, 81912456, 221591423, 502967496, 403284731,
        377738089, 492128779, 746799, 366351977, 190199623, 38066284, 526403762, 650603058,
        454901440,
    ],
    [
        0, 402, 68350375, 30641941, 266024478, 208884256, 571208415, 337765723, 215140626,
        129419325, 480359048, 398051646, 635841659, 214020719, 136986618, 626219915, 49699360,
    ],
    [
        0, 0, 61, 295059608, 141201404, 517024870, 239296485, 527697587, 212906911, 453637228,
        467589845, 144614682, 45134568, 184514320, 644355351, 104784612, 308625792,
    ],
    [
        0, 0, 0, 9, 256449755, 500124311, 479690581, 372802935, 413254725, 487877412, 520263169,
        176791855, 78190744, 291820402, 74998585, 496097732, 59100544,
    ],
    [
        0, 0, 0, 0, 1, 285573662, 455976778, 379818553, 100001224, 448949512, 109507367, 117185012,
        347328982, 522665809, 36908802, 577276849, 64504928,
    ],
    [
        0, 0, 0, 0, 0, 0, 143945778, 651677945, 281429047, 535878743, 264290972, 526964023,
        199595821, 597442702, 499113091, 424550935, 458949280,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 21997789, 294590275, 148640294, 595017589, 210481832, 404203788,
        574729546, 160126051, 430102516, 44963712,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 3361701, 325788598, 30977630, 513969330, 194569730, 164019635,
        136596846, 626087230, 503769920,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 513735, 77223048, 437087610, 300156666, 605448490, 214625350,
        141436834, 379377856,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78508, 646269101, 118408823, 91512303, 209184527, 413102373,
        153715680,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11997, 486083817, 3737691, 294005210, 247894721, 289024608,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1833, 324463681, 385795061, 551597588, 21339008,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 280, 127692781, 389432875, 357132832,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 537767569, 410450016,
    ],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 356826688],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
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
        core::ptr::copy_nonoverlapping(p_p, p_t, 1);
    }
    t
}

#[cfg(target_feature = "avx2")]
const fn fd_ulong_align_up(x: usize, a: usize) -> usize {
    ((x) + ((a) - 1)) & (!((a) - 1))
}

#[cfg(target_feature = "avx2")]
const INTERMEDIATE_SZ_W_PADDING_32: usize = fd_ulong_align_up(INTERMEDIATE_SZ_32, 4);
#[cfg(target_feature = "avx2")]
const INTERMEDIATE_SZ_W_PADDING_64: usize = fd_ulong_align_up(INTERMEDIATE_SZ_64, 4);

#[cfg(not(target_feature = "avx2"))]
const INTERMEDIATE_SZ_W_PADDING_32: usize = INTERMEDIATE_SZ_32;
#[cfg(not(target_feature = "avx2"))]
const INTERMEDIATE_SZ_W_PADDING_64: usize = INTERMEDIATE_SZ_64;

#[inline(always)]
fn fd_ulong_store_if(c: bool, p: *mut u8, v: u8) {
    if c {
        unsafe { *p = v };
    }
}

#[cfg_attr(target_feature = "avx2", repr(align(32)))]
#[repr(C)]
struct Intermediate<const INTERMEDIATE_SZ_W_PADDING: usize>([u64; INTERMEDIATE_SZ_W_PADDING]);

#[cfg(target_feature = "avx2")]
#[inline(always)]
fn in_leading_0s_32_avx(bytes: *const u8) -> u64 {
    let bytes_ = wuc_ldu(bytes);
    count_leading_zeros_32(bytes_)
}

#[cfg(target_feature = "avx2")]
#[inline(always)]
fn in_leading_0s_64_avx(bytes: *const u8) -> u64 {
    let bytes_0 = wuc_ldu(bytes);
    let bytes_1 = wuc_ldu(unsafe { bytes.offset(32) });
    count_leading_zeros_64(bytes_0, bytes_1)
}

#[cfg(not(target_feature = "avx2"))]
#[inline(always)]
fn in_leading_0s_scalar<const BYTE_CNT: usize>(bytes: *const u8) -> usize {
    let mut in_leading_0s = 0;
    while in_leading_0s < BYTE_CNT {
        if unsafe { bytes.add(in_leading_0s).read() != 0 } {
            break;
        }
        in_leading_0s += 1;
    }
    in_leading_0s
}

#[inline(always)]
fn add_binary_to_intermediate<const INTERMEDIATE_SZ_W_PADDING: usize, const BINARY_SZ: usize>(
    intermediate: &mut Intermediate<INTERMEDIATE_SZ_W_PADDING>,
    j: usize,
    binary: [u32; BINARY_SZ],
    i: usize,
    multiplier: u64,
) {
    intermediate.0[j + 1] += binary[i] as u64 * multiplier;
}

#[inline]
pub fn base58_encode_64(bytes: *const u8, opt_len: *mut u8, out: *mut i8) -> *mut i8 {
    let in_leading_0s = {
        #[cfg(target_feature = "avx2")]
        {
            in_leading_0s_64_avx(bytes)
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            in_leading_0s_scalar::<N_64>(bytes)
        }
    };
    let binary = make_binary_array::<BINARY_SZ_64>(bytes);
    /* Convert to the intermediate format:
      X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
    Initially, we don't require intermediate[i] < 58^5, but we do want
    to make sure the sums don't overflow. */
    let mut intermediate = init_intermediate_array::<INTERMEDIATE_SZ_W_PADDING_64>();

    /* If we do it the same way as the 32B conversion, intermediate[16]
    can overflow when the input is sufficiently large.  We'll do a
    mini-reduction after the first 8 steps.  After the first 8 terms,
    the largest intermediate[16] can be is 2^63.87.  Then, after
    reduction it'll be at most 58^5, and after adding the last terms,
    it won't exceed 2^63.1.  We do need to be cautious that the
    mini-reduction doesn't cause overflow in intermediate[15] though.
    Pre-mini-reduction, it's at most 2^63.05.  The mini-reduction adds
    at most 2^64/58^5, which is negligible.  With the final terms, it
    won't exceed 2^63.69, which is fine. Other terms are less than
    2^63.76, so no problems there. */
    for i in 0..8 {
        for j in 0..INTERMEDIATE_SZ_64 - 1 {
            let multiplier = unsafe { *ENC_TABLE_64.get_unchecked(i).get_unchecked(j) } as u64;
            add_binary_to_intermediate(&mut intermediate, j, binary, i, multiplier);
        }
    }
    /* Mini-reduction */
    intermediate.0[15] += intermediate.0[16] / R1DIV;
    intermediate.0[16] %= R1DIV;
    /* Finish iterations */
    for i in 8..BINARY_SZ_64 {
        for j in 0..INTERMEDIATE_SZ_64 - 1 {
            let multiplier = unsafe { *ENC_TABLE_64.get_unchecked(i).get_unchecked(j) as u64 };
            add_binary_to_intermediate(&mut intermediate, j, binary, i, multiplier);
        }
    }
    adjust_intermediate_array::<INTERMEDIATE_SZ_W_PADDING_64, INTERMEDIATE_SZ_64>(
        &mut intermediate,
    );
    let skip = {
        #[cfg(not(target_feature = "avx2"))]
        {
            intermediate_to_base58_scalar::<
                INTERMEDIATE_SZ_W_PADDING_64,
                RAW58_SZ_64,
                INTERMEDIATE_SZ_64,
            >(&intermediate, in_leading_0s, out)
        }
        #[cfg(target_feature = "avx2")]
        {
            let intermediate_ptr = intermediate.0.as_ptr() as *const i64;
            let raw0 = intermediate_to_raw(wl_ld(intermediate_ptr));
            let raw1 = intermediate_to_raw(wl_ld(unsafe { intermediate_ptr.offset(4) }));
            let raw2 = intermediate_to_raw(wl_ld(unsafe { intermediate_ptr.offset(8) }));
            let raw3 = intermediate_to_raw(wl_ld(unsafe { intermediate_ptr.offset(12) }));
            let raw4 = intermediate_to_raw(wl_ld(unsafe { intermediate_ptr.offset(16) }));
            let (compact0, compact1, compact2) = ten_per_slot_down_64(raw0, raw1, raw2, raw3, raw4);
            let raw_leading_0s_part1 = count_leading_zeros_64(compact0, compact1);
            let raw_leading_0s_part2 = count_leading_zeros_26(compact2);
            let raw_leading_0s = if raw_leading_0s_part1 < 64 {
                raw_leading_0s_part1
            } else {
                64 + raw_leading_0s_part2
            };
            let base58_0 = raw_to_base58(compact0);
            let base58_1 = raw_to_base58(compact1);
            let base58_2 = raw_to_base58(compact2);
            let skip = raw_leading_0s - in_leading_0s;
            /* We'll do something similar.  The final string is between 64 and 88
            characters, so skip is [2, 26].
            */
            let w_skip = wl_bcast(skip as i64);
            let mod8_mask = wl_bcast(7);
            let compare = wl(0, 1, 2, 3);
            let shift_qty = wl_shl::<3>(wl_and(w_skip, mod8_mask)); /* bytes->bits */
            let shifted = wl_shru_vector(base58_0, shift_qty);
            let skip_div8 = wl_shru::<3>(w_skip);
            let mask1 = wl_eq(skip_div8, compare);
            let mask2 = wl_gt(compare, skip_div8);
            unsafe {
                _mm256_maskstore_epi64(
                    (out.offset(-8 * (skip as isize / 8))) as *mut i64,
                    mask1,
                    shifted,
                )
            };
            unsafe {
                _mm256_maskstore_epi64(out.offset(-(skip as isize)) as *mut i64, mask2, base58_0)
            };

            unsafe { wuc_stu(out.offset(32 - skip as isize) as *mut u8, base58_1) };

            let last = unsafe { _mm_bslli_si128(_mm256_extractf128_si256(base58_2, 1), 6) };
            unsafe {
                _mm_storeu_si128(
                    out.offset(64 + 16 - 6 - skip as isize) as *mut __m128i,
                    last,
                )
            };
            unsafe {
                _mm_storeu_si128(
                    out.offset(64 - skip as isize) as *mut __m128i,
                    _mm256_extractf128_si256(base58_2, 0),
                )
            };
            skip
        }
    };
    unsafe {
        *out.add(RAW58_SZ_64 - skip as usize) = '\0' as i8;
    }
    fd_ulong_store_if(!opt_len.is_null(), opt_len, RAW58_SZ_64 as u8 - skip as u8);
    out
}

#[inline]
pub fn base58_encode_32(bytes: *const u8, opt_len: *mut u8, out: *mut i8) -> *mut i8 {
    let in_leading_0s = {
        #[cfg(target_feature = "avx2")]
        {
            in_leading_0s_32_avx(bytes)
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            in_leading_0s_scalar::<N_32>(bytes)
        }
    };
    let binary = make_binary_array::<BINARY_SZ_32>(bytes);
    /* Convert to the intermediate format:
      X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
    Initially, we don't require intermediate[i] < 58^5, but we do want
    to make sure the sums don't overflow. */
    let mut intermediate = init_intermediate_array::<INTERMEDIATE_SZ_W_PADDING_32>();
    for i in 0..BINARY_SZ_32 {
        for j in 0..INTERMEDIATE_SZ_32 - 1 {
            let multiplier = unsafe { *ENC_TABLE_32.get_unchecked(i).get_unchecked(j) as u64 };
            add_binary_to_intermediate(&mut intermediate, j, binary, i, multiplier);
        }
    }
    adjust_intermediate_array::<INTERMEDIATE_SZ_W_PADDING_32, INTERMEDIATE_SZ_32>(
        &mut intermediate,
    );
    let skip = {
        #[cfg(not(target_feature = "avx2"))]
        {
            intermediate_to_base58_scalar::<
                INTERMEDIATE_SZ_W_PADDING_32,
                RAW58_SZ_32,
                INTERMEDIATE_SZ_32,
            >(&intermediate, in_leading_0s, out)
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
            let skip = raw_leading_0s - in_leading_0s as u64;
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
        *out.add(RAW58_SZ_32 - skip as usize) = '\0' as i8;
    }
    fd_ulong_store_if(!opt_len.is_null(), opt_len, RAW58_SZ_32 as u8 - skip as u8);
    out
}

#[cfg(not(target_feature = "avx2"))]
fn intermediate_to_base58_scalar<
    const INTERMEDIATE_SZ_W_PADDING: usize,
    const RAW58_SZ: usize,
    const INTERMEDIATE_SZ: usize,
>(
    intermediate: &Intermediate<INTERMEDIATE_SZ_W_PADDING>,
    in_leading_0s: usize,
    out: *mut i8,
) -> usize {
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
        raw_base58[5 * i + 4] = (v % 58) as u8;
        raw_base58[5 * i + 3] = ((v / 58) % 58) as u8;
        raw_base58[5 * i + 2] = ((v / 3364) % 58) as u8;
        raw_base58[5 * i + 1] = ((v / 195112) % 58) as u8;
        raw_base58[5 * i] = (v / 11316496) as u8; /* We know this one is less than 58 */
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
            *out.add(i) = BASE58_CHARS[raw_base58[skip + i] as usize];
        }
    }
    skip
}

#[inline(always)]
fn adjust_intermediate_array<
    const INTERMEDIATE_SZ_W_PADDING: usize,
    const INTERMEDIATE_SZ: usize,
>(
    intermediate: &mut Intermediate<INTERMEDIATE_SZ_W_PADDING>,
) {
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
        intermediate.0[i - 1] += intermediate.0[i] / R1DIV;
        intermediate.0[i] %= R1DIV;
    }
}

#[inline(always)]
fn init_intermediate_array<const INTERMEDIATE_SZ_W_PADDING: usize>(
) -> Intermediate<INTERMEDIATE_SZ_W_PADDING> {
    Intermediate([0u64; INTERMEDIATE_SZ_W_PADDING])
}

#[inline(always)]
fn make_binary_array<const BINARY_SZ: usize>(bytes: *const u8) -> [u32; BINARY_SZ] {
    /* X = sum_i bytes[i] * 2^(8*(BYTE_CNT-1-i)) */

    /* Convert N to 32-bit limbs:
    X = sum_i binary[i] * 2^(32*(BINARY_SZ-1-i)) */
    let mut binary = [0u32; BINARY_SZ];
    for i in 0..BINARY_SZ {
        unsafe {
            *binary.get_unchecked_mut(i) =
                fd_uint_bswap(fd_uint_load_4(bytes.add(i * core::mem::size_of::<u32>())));
        }
    }
    binary
}

#[inline(always)]
#[cold]
fn cold() {}

#[inline(always)]
fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    InvalidChar(i8),
    TooLong,
    LargestTermTooHigh,
    WhatToCallThis,
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
            DecodeError::LargestTermTooHigh {} => {
                formatter.write_str("Largest term greater than 2^32")
            }
            DecodeError::WhatToCallThis {} => formatter.write_str("What to call this"),
            DecodeError::WhatToCallThisToo {} => formatter.write_str("What to call this too"),
        }
    }
}

#[inline]
pub fn base58_decode_32(encoded: *const i8, out: *mut u8) -> Result<*mut u8, DecodeError> {
    base58_decode::<BASE58_ENCODED_32_SZ, RAW58_SZ_32, INTERMEDIATE_SZ_32, BINARY_SZ_32, N_32>(
        encoded,
        out,
        &DEC_TABLE_32,
    )
}

#[inline]
pub fn base58_decode_64(encoded: *const i8, out: *mut u8) -> Result<*mut u8, DecodeError> {
    base58_decode::<BASE58_ENCODED_64_SZ, RAW58_SZ_64, INTERMEDIATE_SZ_64, BINARY_SZ_64, N_64>(
        encoded,
        out,
        &DEC_TABLE_64,
    )
}

#[inline]
fn base58_decode<
    const ENCODED_SZ: usize,
    const RAW58_SZ: usize,
    const INTERMEDIATE_SZ: usize,
    const BINARY_SZ: usize,
    const N: usize,
>(
    encoded: *const i8,
    out: *mut u8,
    dec_table: &[[u32; BINARY_SZ]; INTERMEDIATE_SZ],
) -> Result<*mut u8, DecodeError> {
    /* Validate string and count characters before the nul terminator */
    let mut char_cnt = 0usize;
    while char_cnt < ENCODED_SZ {
        let c = unsafe { *encoded.add(char_cnt) };
        if c == 0 {
            break;
        }
        /* If c<'1', this will underflow and idx will be huge */
        let idx = (c as u8 as u64).wrapping_sub(BASE58_INVERSE_TABLE_OFFSET as u64);
        let idx = idx.min(BASE58_INVERSE_TABLE_SENTINEL as u64);
        char_cnt += 1;
        if unlikely(BASE58_INVERSE[idx as usize] == BASE58_INVALID_CHAR) {
            return Err(DecodeError::InvalidChar(c));
        }
    }
    if unlikely(char_cnt == ENCODED_SZ) {
        /* too long */
        return Err(DecodeError::TooLong);
    }
    /* X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */
    let mut raw_base58 = [0u8; RAW58_SZ];
    /* Prepend enough 0s to make it exactly RAW58_SZ characters */
    let prepend_0 = RAW58_SZ - char_cnt;
    for j in 0..RAW58_SZ {
        raw_base58[j] = if j < prepend_0 {
            0
        } else {
            BASE58_INVERSE[(unsafe { *encoded.add(j - prepend_0) }
                - BASE58_INVERSE_TABLE_OFFSET as i8) as usize]
        };
    }
    /* Convert to the intermediate format (base 58^5):
    X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */
    let mut intermediate = [0u64; INTERMEDIATE_SZ];
    for i in 0..INTERMEDIATE_SZ {
        intermediate[i] = raw_base58[5 * i] as u64 * 11316496
            + raw_base58[5 * i + 1] as u64 * 195112
            + raw_base58[5 * i + 2] as u64 * 3364
            + raw_base58[5 * i + 3] as u64 * 58
            + raw_base58[5 * i + 4] as u64;
    }
    /* Using the table, convert to overcomplete base 2^32 (terms can be
    larger than 2^32).  We need to be careful about overflow.

    For N==32, the largest anything in binary can get is binary[7]:
    even if intermediate[i]==58^5-1 for all i, then binary[7] < 2^63.

    For N==64, the largest anything in binary can get is binary[13]:
    even if intermediate[i]==58^5-1 for all i, then binary[13] <
    2^63.998.  Hanging in there, just by a thread! */
    let mut binary = [0u64; BINARY_SZ];
    for j in 0..BINARY_SZ {
        let mut acc = 0u64;
        for i in 0..INTERMEDIATE_SZ {
            acc += unsafe {
                intermediate.get_unchecked(i) * *dec_table.get_unchecked(i).get_unchecked(j) as u64
            };
        }
        unsafe { *binary.get_unchecked_mut(j) = acc };
    }
    /* Make sure each term is less than 2^32.

    For N==32, we have plenty of headroom in binary, so overflow is
    not a concern this time.

    For N==64, even if we add 2^32 to binary[13], it is still 2^63.998,
    so this won't overflow. */
    for i in (1..BINARY_SZ).rev() {
        binary[i - 1] += binary[i] >> 32;
        binary[i] &= 0xFFFFFFFF;
    }
    /* If the largest term is 2^32 or bigger, it means N is larger than
    what can fit in BYTE_CNT bytes.  This can be triggered, by passing
    a base58 string of all 'z's for example. */
    if unlikely(binary[0] > 0xFFFFFFFF) {
        return Err(DecodeError::LargestTermTooHigh);
    }
    /* Convert each term to big endian for the final output */
    let out_as_uint = out as *mut u32;
    for i in 0..BINARY_SZ {
        unsafe {
            let swapped = fd_uint_bswap(*binary.get_unchecked(i) as u32);
            *out_as_uint.add(i) = swapped;
        }
    }
    /* Make sure the encoded version has the same number of leading '1's
    as the decoded version has leading 0s. The check doesn't read past
    the end of encoded, because '\0' != '1', so it will return NULL. */
    let mut leading_zero_cnt = 0u64;
    while leading_zero_cnt < N as u64 {
        if unsafe { *out.offset(leading_zero_cnt as isize) != 0 } {
            break;
        }
        if unlikely(unsafe { *encoded.offset(leading_zero_cnt as isize) != ('1' as i8) }) {
            return Err(DecodeError::WhatToCallThis);
        }
        leading_zero_cnt += 1;
    }
    if unlikely(unsafe { *encoded.offset(leading_zero_cnt as isize) == ('1' as i8) }) {
        return Err(DecodeError::WhatToCallThisToo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_32_to_string(
        bytes: &[u8; 32],
        len: &mut u8,
        buf: &mut [i8; BASE58_ENCODED_32_SZ],
    ) -> String {
        let res = base58_encode_32(bytes.as_ptr(), len, buf.as_mut_ptr());
        let as_slice = unsafe { core::slice::from_raw_parts(res, *len as usize) };
        let collected: String = as_slice.iter().map(|c| *c as u8 as char).collect();
        collected
    }

    fn check_encode_decode_32(
        bytes: &[u8; 32],
        len: &mut u8,
        buf: &mut [i8; BASE58_ENCODED_32_SZ],
        expected_len: u8,
        encoded: &str,
    ) {
        assert_eq!(&encode_32_to_string(&bytes, len, buf), encoded);
        assert_eq!(*len, expected_len);
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let null_terminated_ptr = null_terminated.as_slice().as_ptr();
        let mut decoded = [0u8; 32];
        base58_decode_32(null_terminated_ptr as *const i8, decoded.as_mut_ptr()).unwrap();
        assert_eq!(&decoded, bytes);
    }

    fn check_encode_decode_64(
        bytes: &[u8; 64],
        len: &mut u8,
        buf: &mut [i8; BASE58_ENCODED_64_SZ],
        expected_len: u8,
        encoded: &str,
    ) {
        assert_eq!(&encode_64_to_string(&bytes, len, buf), encoded);
        assert_eq!(*len, expected_len);
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let null_terminated_ptr = null_terminated.as_slice().as_ptr();
        let mut decoded = [0u8; 64];
        base58_decode_64(null_terminated_ptr as *const i8, decoded.as_mut_ptr()).unwrap();
        assert_eq!(&decoded, bytes);
    }

    fn check_bad_decode_32(expected_err: DecodeError, encoded: &str) {
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let null_terminated_ptr = null_terminated.as_slice().as_ptr();
        let mut decoded = [0u8; 32];
        let err =
            base58_decode_32(null_terminated_ptr as *const i8, decoded.as_mut_ptr()).unwrap_err();
        assert_eq!(err, expected_err);
    }

    fn check_bad_decode_64(expected_err: DecodeError, encoded: &str) {
        let mut null_terminated = encoded.as_bytes().to_vec();
        null_terminated.push(b'\0');
        let null_terminated_ptr = null_terminated.as_slice().as_ptr();
        let mut decoded = [0u8; 64];
        let err =
            base58_decode_64(null_terminated_ptr as *const i8, decoded.as_mut_ptr()).unwrap_err();
        assert_eq!(err, expected_err);
    }

    fn encode_64_to_string(
        bytes: &[u8; 64],
        len: &mut u8,
        buf: &mut [i8; BASE58_ENCODED_64_SZ],
    ) -> String {
        let res = base58_encode_64(bytes.as_ptr(), len, buf.as_mut_ptr());
        let as_slice = unsafe { core::slice::from_raw_parts(res, *len as usize) };
        let collected: String = as_slice.iter().map(|c| *c as u8 as char).collect();
        collected
    }

    #[test]
    fn test_encode_decode_32() {
        let mut buf = [0i8; BASE58_ENCODED_32_SZ];
        let mut len = 0u8;
        let mut bytes = [0u8; 32];
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            32,
            "11111111111111111111111111111111",
        );
        bytes[31] += 1;
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            32,
            "11111111111111111111111111111112",
        );
        bytes[30] += 1;
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            32,
            "1111111111111111111111111111115S",
        );
        let mut bytes = [255u8; 32];
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            44,
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG",
        );
        bytes[31] -= 1;
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            44,
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFF",
        );
        let bytes = [1u8; 32];
        check_encode_decode_32(
            &bytes,
            &mut len,
            &mut buf,
            43,
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
        );
        assert_eq!(len, 43);
    }

    #[test]
    fn test_base58_decode_32() {
        let encoded = b"11111111111111111111111111111112\0";
        let encoded_ptr = encoded.as_ptr();
        assert_eq!(unsafe { *encoded_ptr.offset(31) }, b'2');
        let mut decoded = [0u8; 32];
        let res = base58_decode_32(encoded_ptr as *const i8, decoded.as_mut_ptr()).unwrap();
        let as_slice = unsafe { core::slice::from_raw_parts(res, 32) };
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(as_slice, &expected);
        assert_eq!(as_slice, &decoded);
    }

    #[test]
    fn test_encode_decode_64() {
        let mut buf = [0i8; BASE58_ENCODED_64_SZ];
        let mut len = 0u8;
        let mut bytes = [0u8; 64];
        check_encode_decode_64(
            &bytes,
            &mut len,
            &mut buf,
            64,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        bytes[63] += 1;
        check_encode_decode_64(
            &bytes,
            &mut len,
            &mut buf,
            64,
            "1111111111111111111111111111111111111111111111111111111111111112",
        );
        bytes[62] += 1;
        check_encode_decode_64(
            &bytes,
            &mut len,
            &mut buf,
            64,
            "111111111111111111111111111111111111111111111111111111111111115S",
        );
        let mut bytes = [255; 64];
        check_encode_decode_64(
            &bytes,
            &mut len,
            &mut buf,
            88,
            "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ",
        );
        bytes[63] -= 1;
        check_encode_decode_64(
            &bytes,
            &mut len,
            &mut buf,
            88,
            "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roP",
        );
    }

    #[test]
    fn test_decode_error_32() {
        // check_bad_decode_32(DecodeError::TooLong, "1");
        // check_bad_decode_32(DecodeError::TooLong, "1111111111111111111111111111111");
        // check_bad_decode_32(DecodeError::TooLong, "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJz");
        // check_bad_decode_32(DecodeError::TooLong, "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL");
        check_bad_decode_32(
            DecodeError::TooLong,
            "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4",
        );
        // check_bad_decode_32(DecodeError::TooLong, "111111111111111111111111111111111");
        check_bad_decode_32(
            DecodeError::LargestTermTooHigh,
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFJ",
        ); /* 2nd-smallest 33 byte value that doesn't start with 0x0 */
        // check_bad_decode_32(
        //     DecodeError::TooLong,
        //     "11aEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWx",
        // );
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
        // check_bad_decode_64(DecodeError::TooLong, "1");
        // check_bad_decode_64(DecodeError::TooLong, "111111111111111111111111111111111111111111111111111111111111111");
        // check_bad_decode_64(DecodeError::TooLong, "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA");
        // check_bad_decode_64(DecodeError::TooLong, "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QW");
        check_bad_decode_64(DecodeError::TooLong, "2AFv15MNPuA84RmU66xw2uMzGipcVxNpzAffoacGVvjFue3CBmf633fAWuiP9cwL9C3z3CJiGgRSFjJfeEcA6QWabc");
        // check_bad_decode_64(DecodeError::TooLong, "11111111111111111111111111111111111111111111111111111111111111111");
        check_bad_decode_64(
            DecodeError::LargestTermTooHigh,
            "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roS"
        ); /* 2nd-smallest 65 byte value that doesn't start with 0x0 */

        // check_bad_decode_64(DecodeError::LargestTermTooHigh, "1114tjGcyzrfXw2deDmDAFFaFyss32WRgkYdDJuprrNEL8kc799TrHSQHfE9fv6ZDBUg2dsMJdfYr71hjE4EfjEN"); /* Start with too many '1's */
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
