use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_decode_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_32");
    let string = "2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG";
    let bytes = b"2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG\0";
    let mut out = [0u8; 32];

    group.bench_function("decode_bs58", |b| {
        b.iter(|| bs58::decode(black_box(string)).into_vec())
    });
    group.bench_function("decode_bs58_noalloc", |b| {
        let mut output = [0; 32];
        b.iter(|| bs58::decode(black_box(string)).into(&mut output).unwrap());
    });
    group.bench_function("decode_lou", |b| {
        b.iter(|| fd_bs58::decode_32(black_box(string)))
    });
    group.bench_function("decode_five8", |b| {
        b.iter(|| five8::decode_32(black_box(bytes), black_box(&mut out)))
    });
    group.finish();
}

fn bench_decode_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_64");
    let string =
        "11cgTH4D5e8S3snD444WbbGrkepjTvWMj2jkmCGJtgn3H7qrPb1BnwapxpbGdRtHQh9t9Wbn9t6ZDGHzWpL4df";
    let bytes =
        b"11cgTH4D5e8S3snD444WbbGrkepjTvWMj2jkmCGJtgn3H7qrPb1BnwapxpbGdRtHQh9t9Wbn9t6ZDGHzWpL4df\0";
    let mut out = [0u8; 64];

    group.bench_function("decode_bs58", |b| {
        b.iter(|| bs58::decode(black_box(string)).into_vec())
    });
    group.bench_function("decode_bs58_noalloc", |b| {
        let mut output = [0; 64];
        b.iter(|| bs58::decode(black_box(string)).into(&mut output).unwrap());
    });
    group.bench_function("decode_lou", |b| {
        b.iter(|| fd_bs58::decode_64(black_box(string)))
    });
    group.bench_function("decode_five8", |b| {
        b.iter(|| five8::decode_64(black_box(bytes), black_box(&mut out)))
    });
    group.finish();
}

criterion_group!(benches, bench_decode_32, bench_decode_64);
criterion_main!(benches);
