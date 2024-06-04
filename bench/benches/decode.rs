use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn showcase_decode_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("showcase_decode_32");
    let string = "2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG";
    let bytes = b"2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG";

    group.bench_function("decode_bs58_noalloc", |b| {
        let mut output = [0; 32];
        b.iter(|| bs58::decode(black_box(string)).into(&mut output).unwrap());
    });
    group.bench_function("decode_lou", |b| {
        b.iter(|| fd_bs58::decode_32(black_box(string)))
    });
    group.bench_function("decode_five8", |b| {
        b.iter(|| five8::decode_32(black_box(bytes)))
    });
    group.finish();
}

fn showcase_decode_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("showcase_decode_64");
    let string =
        "11cgTH4D5e8S3snD444WbbGrkepjTvWMj2jkmCGJtgn3H7qrPb1BnwapxpbGdRtHQh9t9Wbn9t6ZDGHzWpL4df";
    let mut out = [0u8; 64];

    group.bench_function("decode_bs58_noalloc", |b| {
        let mut output = [0; 64];
        b.iter(|| bs58::decode(black_box(string)).into(&mut output).unwrap());
    });
    group.bench_function("decode_lou", |b| {
        b.iter(|| fd_bs58::decode_64(black_box(string)))
    });
    group.bench_function("decode_five8", |b| {
        b.iter(|| five8::decode_64(black_box(&mut out)))
    });
    group.finish();
}

fn bench_truncate_swap_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("truncate_swap_64");
    let bytes: [u8; 128] = [
        215, 73, 67, 191, 43, 217, 50, 40, 125, 237, 129, 129, 179, 233, 7, 105, 54, 9, 136, 26,
        210, 248, 126, 172, 119, 202, 94, 23, 28, 184, 110, 212, 114, 22, 220, 173, 177, 235, 44,
        20, 44, 237, 101, 1, 111, 149, 189, 69, 1, 194, 117, 235, 207, 56, 84, 20, 145, 51, 1, 1,
        141, 158, 146, 118, 180, 194, 229, 228, 221, 151, 170, 72, 123, 12, 166, 158, 85, 2, 32,
        54, 133, 131, 207, 56, 189, 221, 212, 186, 194, 29, 32, 56, 70, 105, 105, 51, 244, 135,
        111, 17, 25, 26, 186, 222, 228, 187, 67, 78, 3, 235, 166, 27, 13, 30, 166, 206, 203, 66,
        81, 152, 160, 142, 53, 60, 75, 224, 196, 208,
    ];
    let nums: [u64; 16] = unsafe { core::mem::transmute(bytes) };
    group.bench_function("truncate_and_swap_u64s_64", |b| {
        let mut out = [0u8; 64];
        b.iter(|| five8::truncate_and_swap_u64s_64_pub(black_box(&nums), black_box(&mut out)))
    });
    group.bench_function("truncate_and_swap_u64s_scalar", |b| {
        let mut out = [0u8; 64];
        b.iter(|| {
            five8::truncate_and_swap_u64s_scalar_pub::<16, 64>(
                black_box(&nums),
                black_box(&mut out),
            )
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    showcase_decode_32,
    showcase_decode_64,
    bench_truncate_swap_64
);
criterion_main!(benches);
