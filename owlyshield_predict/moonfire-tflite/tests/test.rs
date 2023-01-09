#[cfg(feature = "edgetpu")]
use moonfire_tflite::edgetpu::{self, version, Devices};
use moonfire_tflite::{Interpreter, Model};

#[test]
#[cfg(feature = "edgetpu")]
fn test_version() {
    println!("edgetpu version: {}", version());
}

#[test]
#[cfg(feature = "edgetpu")]
fn list_devices() {
    let devices = Devices::list();
    println!("{} edge tpu devices:", devices.len());
    for d in &devices {
        println!("device: {d:?}");
    }
}

#[test]
#[cfg(feature = "edgetpu")]
fn create_delegate() {
    let devices = Devices::list();
    if !devices.is_empty() {
        devices[0].create_delegate().unwrap();
    }
}

pub static MODEL: &[u8] = include_bytes!("../testdata/ssd_mobilenet_v1_coco_2018_01_28.tflite");

#[test]
fn create_drop_model() {
    let _m = Model::from_static(MODEL).unwrap();
}

#[test]
fn lifecycle() {
    let m = Model::from_static(MODEL).unwrap();
    let builder = Interpreter::builder();
    let mut interpreter = builder.build(&m, 0, 0).unwrap();
    println!(
        "interpreter with {} inputs, {} outputs",
        interpreter.inputs().len(),
        interpreter.outputs().len()
    );
    let inputs = interpreter.inputs();
    for i in 0..inputs.len() {
        println!("input: {:?}", inputs[i]);
    }
    let outputs = interpreter.outputs();
    for i in 0..outputs.len() {
        println!("output: {:?}", outputs[i]);
    }
}

#[test]
#[cfg(feature = "edgetpu")]
fn lifecycle_edgetpu() {
    static EDGETPU_MODEL: &[u8] = include_bytes!("../testdata/edgetpu.tflite");
    let m = Model::from_static(EDGETPU_MODEL).unwrap();
    let mut builder = Interpreter::builder();
    let devices = edgetpu::Devices::list();
    assert!(
        !devices.is_empty(),
        "need an edge tpu installed to run edge tpu tests"
    );
    let delegate = devices[0].create_delegate().unwrap();
    builder.add_owned_delegate(delegate);
    let mut interpreter = builder.build(&m, 0, 0).unwrap();
    println!(
        "interpreter with {} inputs, {} outputs",
        interpreter.inputs().len(),
        interpreter.outputs().len()
    );
    let inputs = interpreter.inputs();
    for i in 0..inputs.len() {
        println!("input: {:?}", inputs[i]);
    }
    let outputs = interpreter.outputs();
    for i in 0..outputs.len() {
        println!("output: {:?}", outputs[i]);
    }
}
