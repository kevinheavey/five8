pub(crate) const N_32: usize = 32;
pub(crate) const N_64: usize = 64;
pub(crate) const BINARY_SZ_32: usize = N_32 / 4;
pub(crate) const BINARY_SZ_64: usize = N_64 / 4;
pub(crate) const INTERMEDIATE_SZ_32: usize = 9; /* Computed by ceil(log_(58^5) (256^32-1)) */
pub(crate) const INTERMEDIATE_SZ_64: usize = 18; /* Computed by ceil(log_(58^5) (256^64-1)) */
pub(crate) const RAW58_SZ_32: usize = INTERMEDIATE_SZ_32 * 5;
pub(crate) const RAW58_SZ_64: usize = INTERMEDIATE_SZ_64 * 5;
