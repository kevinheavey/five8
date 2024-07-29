use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn showcase_encode_32(c: &mut Criterion) {
    let mut group = c.benchmark_group("showcase_encode_32");
    let bytes = &[
        24, 243, 6, 223, 230, 153, 210, 8, 92, 137, 123, 67, 164, 197, 79, 196, 125, 43, 183, 85,
        103, 91, 232, 167, 73, 131, 104, 131, 0, 101, 214, 231,
    ];
    let string = "2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG";
    let mut buf = [0u8; 44];
    let mut len = 0u8;

    group.bench_function("encode_bs58_noalloc", |b| {
        let mut output = String::with_capacity(string.len());
        b.iter(|| bs58::encode(black_box(&bytes)).into(&mut output));
    });
    group.bench_function("encode_lou", |b| {
        b.iter(|| fd_bs58::encode_32(black_box(&bytes)))
    });
    group.bench_function("encode_five8", |b| {
        b.iter(|| {
            five8::encode_32(
                black_box(bytes),
                black_box(Some(&mut len)),
                black_box(&mut buf),
            )
        })
    });
    group.finish();
}

fn showcase_encode_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("showcase_encode_64");
    let bytes = &[
        0, 0, 10, 85, 198, 191, 71, 18, 5, 54, 6, 255, 181, 32, 227, 150, 208, 3, 157, 135, 222,
        67, 50, 23, 237, 51, 240, 123, 34, 148, 111, 84, 98, 162, 236, 133, 31, 93, 185, 142, 108,
        41, 191, 1, 138, 6, 192, 0, 46, 93, 25, 65, 243, 223, 225, 225, 85, 55, 82, 251, 109, 132,
        165, 2,
    ];
    let string =
        "11cgTH4D5e8S3snD444WbbGrkepjTvWMj2jkmCGJtgn3H7qrPb1BnwapxpbGdRtHQh9t9Wbn9t6ZDGHzWpL4df";
    let mut buf = [0u8; 88];
    let mut len = 0u8;

    group.bench_function("encode_bs58_noalloc", |b| {
        let mut output = String::with_capacity(string.len());
        b.iter(|| bs58::encode(black_box(&bytes)).into(&mut output));
    });
    group.bench_function("encode_lou", |b| {
        b.iter(|| fd_bs58::encode_64(black_box(&bytes)))
    });
    group.bench_function("encode_five8", |b| {
        b.iter(|| {
            five8::encode_64(
                black_box(bytes),
                black_box(Some(&mut len)),
                black_box(&mut buf),
            )
        })
    });
    group.finish();
}

fn encode_64_scalar_breakdown(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_64_scalar_breakdown");
    let bytes_64: [u8; 64] = [
        0, 0, 10, 85, 198, 191, 71, 18, 5, 54, 6, 255, 181, 32, 227, 150, 208, 3, 157, 135, 222,
        67, 50, 23, 237, 51, 240, 123, 34, 148, 111, 84, 98, 162, 236, 133, 31, 93, 185, 142, 108,
        41, 191, 1, 138, 6, 192, 0, 46, 93, 25, 65, 243, 223, 225, 225, 85, 55, 82, 251, 109, 132,
        165, 2,
    ];
    let bytes_ptr_64 = &bytes_64 as *const u8;
    let binary = five8::make_binary_array_64_pub(&bytes_64);
    let in_leading_0s = five8::in_leading_0s_scalar_pub::<64>(bytes_ptr_64);
    let intermediate = five8::make_intermediate_array_64_pub(binary);
    let mut out = [0u8; 88];
    group.bench_function("in_leading_0s_scalar_64", |b| {
        b.iter(|| five8::in_leading_0s_scalar_pub::<64>(black_box(bytes_ptr_64)));
    });
    group.bench_function("make_binary_array_64", |b| {
        b.iter(|| five8::make_binary_array_64_pub(black_box(&bytes_64)));
    });
    group.bench_function("make_intermediate_array_64", |b| {
        b.iter(|| five8::make_intermediate_array_64_pub(black_box(binary)));
    });
    group.bench_function("intermediate_to_base58_scalar_64", |b| {
        b.iter(|| {
            five8::intermediate_to_base58_scalar_64_pub(&intermediate, in_leading_0s, &mut out)
        });
    });
    group.finish();
}

fn encode_32_breakdown(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_32_breakdown");
    let bytes: [u8; 32] = [
        0, 0, 10, 85, 198, 191, 71, 18, 5, 54, 6, 255, 181, 32, 227, 150, 208, 3, 157, 135, 222,
        67, 50, 23, 237, 51, 240, 123, 34, 148, 111, 84,
    ];
    let bytes_ptr = &bytes as *const u8;
    let binary = five8::make_binary_array_32_pub(&bytes);
    let in_leading_0s = five8::in_leading_0s_scalar_pub::<32>(bytes_ptr);
    let intermediate = five8::make_intermediate_array_32_pub(binary);
    let mut out = [0u8; 44];
    group.bench_function("in_leading_0s_32", |b| {
        b.iter(|| five8::in_leading_0s_32_pub(black_box(bytes_ptr)));
    });
    group.bench_function("make_binary_array_32", |b| {
        b.iter(|| five8::make_binary_array_32_pub(black_box(&bytes)));
    });
    group.bench_function("make_intermediate_array_32", |b| {
        b.iter(|| five8::make_intermediate_array_32_pub(black_box(binary)));
    });
    group.bench_function("intermediate_to_base58_32", |b| {
        b.iter(|| {
            five8::intermediate_to_base58_32_pub(&intermediate, in_leading_0s, &mut out)
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    showcase_encode_32,
    showcase_encode_64,
    encode_64_scalar_breakdown,
    encode_32_breakdown
);
criterion_main!(benches);
