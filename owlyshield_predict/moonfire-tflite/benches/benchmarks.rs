use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "edgetpu")]
use moonfire_tflite::edgetpu::{version, Devices};
use moonfire_tflite::{Interpreter, Model};

pub static MODEL: &[u8] = include_bytes!("../testdata/ssd_mobilenet_v1_coco_2018_01_28.tflite");

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("test_version", |b| {
        b.iter(|| {
            println!("edgetpu version: {}", black_box(version()));
        })
    });

    c.bench_function("list_devices", |b| {
        b.iter(|| {
            let devices = black_box(Devices::list());
            println!("{} edge tpu devices:", black_box(devices.len()));
            for d in black_box(&devices) {
                println!("device: {d:?}");
            }
        })
    });

    c.bench_function("create_delegate", |b| {
        b.iter(|| {
            let devices = black_box(Devices::list());
            if !devices.is_empty() {
                devices[0].create_delegate().unwrap();
            }
        })
    });

    c.bench_function("create_drop_model", |b| {
        b.iter(|| {
            let _m = black_box(Model::from_static(MODEL).unwrap());
        })
    });

    c.bench_function("lifecycle", |b| {
        b.iter(|| {
            let m = black_box(Model::from_static(MODEL).unwrap());
            let builder = black_box(Interpreter::builder());
            let mut interpreter = black_box(builder.build(&m, 0, 0).unwrap());
            println!(
                "interpreter with {} inputs, {} outputs",
                interpreter.inputs().len(),
                interpreter.outputs().len()
            );
            let inputs = black_box(interpreter.inputs());
            for i in 0..inputs.len() {
                println!("input: {:?}", inputs[i]);
            }
            let outputs = black_box(interpreter.outputs());
            for i in 0..outputs.len() {
                println!("output: {:?}", outputs[i]);
            }
        })
    });

    c.bench_function("lifecycle_edgetpu", |b| {
        b.iter(|| {
            static EDGETPU_MODEL: &[u8] = include_bytes!("../testdata/edgetpu.tflite");
            let m = black_box(Model::from_static(EDGETPU_MODEL).unwrap());
            let mut builder = black_box(Interpreter::builder());
            let devices = black_box(Devices::list());
            assert!(
                !devices.is_empty(),
                "need an edge tpu installed to run edge tpu tests"
            );
            let delegate = black_box(devices[0].create_delegate().unwrap());
            builder.add_owned_delegate(black_box(delegate));
            let mut interpreter = black_box(builder.build(&m, 0, 0).unwrap());
            println!(
                "interpreter with {} inputs, {} outputs",
                interpreter.inputs().len(),
                interpreter.outputs().len()
            );
            let inputs = black_box(interpreter.inputs());
            for i in 0..inputs.len() {
                println!("input: {:?}", inputs[i]);
            }
            let outputs = black_box(interpreter.outputs());
            for i in 0..outputs.len() {
                println!("output: {:?}", outputs[i]);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
