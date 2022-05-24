// Copyright (C) 2020 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::ffi::{CStr, c_void};
use std::marker::PhantomData;
use std::os::raw::c_char;
use std::ptr;
use std::ffi::CString;

#[cfg(feature = "edgetpu")]
pub mod edgetpu;

// Opaque types from the C interface.
// https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
#[repr(C)]
struct TfLiteDelegate {
    _private: [u8; 0],
}
#[repr(C)]
struct TfLiteInterpreter {
    _private: [u8; 0],
}
#[repr(C)]
struct TfLiteInterpreterOptions {
    _private: [u8; 0],
}
#[repr(C)]
struct TfLiteModel {
    _private: [u8; 0],
}
#[repr(C)]
pub struct Tensor {
    _private: [u8; 0],
} // aka TfLiteTensor

// Type, aka TfLiteType
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum Type {
    NoType = 0,
    Float32 = 1,
    Int32 = 2,
    UInt8 = 3,
    Int64 = 4,
    String = 5,
    Bool = 6,
    Int16 = 7,
    Complex64 = 8,
    Int8 = 9,
    Float16 = 10,
}

#[derive(Copy, Clone)]
#[repr(transparent)]
struct TfLiteStatus(libc::c_int);

//#[link(name = r"C:\Users\lesco\IdeaProjects\owlyshield_ransom\tensorflowlite_c")]
extern "C" {
    fn TfLiteModelCreate(model_data: *const u8, model_size: usize) -> *mut TfLiteModel;
    fn TfLiteModelCreateFromFile(model_path: *const c_char) -> *mut TfLiteModel;
    fn TfLiteModelDelete(model: *mut TfLiteModel);

    fn TfLiteInterpreterOptionsCreate() -> *mut TfLiteInterpreterOptions;
    fn TfLiteInterpreterOptionsDelete(interpreter: *mut TfLiteInterpreterOptions);
    fn TfLiteInterpreterOptionsAddDelegate(
        options: *mut TfLiteInterpreterOptions,
        delegate: *mut TfLiteDelegate,
    );

    fn TfLiteInterpreterCreate(
        model: *const TfLiteModel,
        options: *const TfLiteInterpreterOptions,
    ) -> *mut TfLiteInterpreter;
    fn TfLiteInterpreterDelete(interpreter: *mut TfLiteInterpreter);
    fn TfLiteInterpreterAllocateTensors(interpreter: *mut TfLiteInterpreter) -> TfLiteStatus;
    fn TfLiteInterpreterGetInputTensorCount(interpreter: *const TfLiteInterpreter) -> libc::c_int;
    fn TfLiteInterpreterGetInputTensor(
        interpreter: *const TfLiteInterpreter,
        input_index: i32,
    ) -> *mut Tensor;
    fn TfLiteInterpreterInvoke(interpreter: *mut TfLiteInterpreter) -> TfLiteStatus;
    fn TfLiteInterpreterGetOutputTensorCount(interpreter: *const TfLiteInterpreter) -> libc::c_int;
    fn TfLiteInterpreterGetOutputTensor(
        interpreter: *const TfLiteInterpreter,
        output_index: i32,
    ) -> *const Tensor;

    fn TfLiteTensorType(tensor: *const Tensor) -> Type;
    fn TfLiteTensorNumDims(tensor: *const Tensor) -> i32;
    fn TfLiteTensorDim(tensor: *const Tensor, dim_index: i32) -> i32;
    fn TfLiteTensorByteSize(tensor: *const Tensor) -> usize;
    fn TfLiteTensorData(tensor: *const Tensor) -> *mut u8;
    fn TfLiteTensorName(tensor: *const Tensor) -> *const c_char;
    fn TfLiteInterpreterResizeInputTensor(interpreter: *const TfLiteInterpreter, input_index: usize, input_data: *const c_void, input_data_size: usize) -> TfLiteStatus;

   // fn TfLiteTypeGetName(type_: Type) -> *const c_char;
}

impl TfLiteStatus {
    fn to_result(self) -> Result<(), ()> {
        match self.0 {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}

pub struct InterpreterBuilder<'a> {
    options: ptr::NonNull<TfLiteInterpreterOptions>,
    owned_delegates: Vec<Delegate>,
    _delegate_refs: PhantomData<&'a ()>,
}

impl<'a> InterpreterBuilder<'a> {
    pub fn new() -> Self {
        Self {
            options: ptr::NonNull::new(unsafe { TfLiteInterpreterOptionsCreate() }).unwrap(),
            owned_delegates: Vec::new(),
            _delegate_refs: PhantomData,
        }
    }

    pub fn add_borrowed_delegate(&mut self, d: &'a Delegate) {
        unsafe { TfLiteInterpreterOptionsAddDelegate(self.options.as_ptr(), d.delegate.as_ptr()) }
    }

    pub fn add_owned_delegate(&mut self, d: Delegate) {
        unsafe { TfLiteInterpreterOptionsAddDelegate(self.options.as_ptr(), d.delegate.as_ptr()) }
        self.owned_delegates.push(d);
    }

    pub fn build(mut self, model: &Model, seq_len: usize, vector_len: usize) -> Result<Interpreter<'a>, ()> {
        let interpreter =
            unsafe { TfLiteInterpreterCreate(model.0.as_ptr(), self.options.as_ptr()) };
        let interpreter = Interpreter {
            interpreter: ptr::NonNull::new(interpreter).ok_or(())?,
            _owned_delegates: std::mem::replace(&mut self.owned_delegates, Vec::new()),
            _delegate_refs: PhantomData,
        };
        let input_data = vec![1, seq_len as u32, vector_len as u32];
        unsafe { TfLiteInterpreterResizeInputTensor(interpreter.interpreter.as_ptr(), 0, input_data.as_ptr() as *const c_void, 3); }
        unsafe { TfLiteInterpreterAllocateTensors(interpreter.interpreter.as_ptr()) }
            .to_result()?;
        Ok(interpreter)
    }
}

impl<'a> Drop for InterpreterBuilder<'a> {
    fn drop(&mut self) {
        unsafe { TfLiteInterpreterOptionsDelete(self.options.as_ptr()) };
    }
}

pub struct Interpreter<'a> {
    interpreter: ptr::NonNull<TfLiteInterpreter>,
    _owned_delegates: Vec<Delegate>,
    _delegate_refs: PhantomData<&'a ()>,
}

impl<'a> Interpreter<'a> {
    pub fn builder() -> InterpreterBuilder<'a> {
        InterpreterBuilder::new()
    }

    pub fn invoke(&mut self) -> Result<(), ()> {
        unsafe { TfLiteInterpreterInvoke(self.interpreter.as_ptr()) }.to_result()
    }

    pub fn inputs(&mut self) -> InputTensors {
        let len = usize::try_from(unsafe {
            TfLiteInterpreterGetInputTensorCount(self.interpreter.as_ptr())
        })
        .unwrap();
        InputTensors {
            interpreter: self,
            len,
        }
    }

    pub fn outputs(&self) -> OutputTensors {
        let len = usize::try_from(unsafe {
            TfLiteInterpreterGetOutputTensorCount(self.interpreter.as_ptr())
        })
        .unwrap();
        OutputTensors {
            interpreter: self,
            len,
        }
    }
}

impl<'a> Drop for Interpreter<'a> {
    fn drop(&mut self) {
        unsafe { TfLiteInterpreterDelete(self.interpreter.as_ptr()) };
    }
}

unsafe impl<'a> Send for Interpreter<'a> {}
unsafe impl<'a> Sync for Interpreter<'a> {}

pub struct InputTensors<'i> {
    interpreter: &'i Interpreter<'i>,
    len: usize,
}

impl<'i> InputTensors<'i> {
    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'i> std::ops::Index<usize> for InputTensors<'i> {
    type Output = Tensor;

    fn index(&self, index: usize) -> &Tensor {
        let index = i32::try_from(index).unwrap();
        unsafe { &*TfLiteInterpreterGetInputTensor(self.interpreter.interpreter.as_ptr(), index) }
    }
}

impl<'i> std::ops::IndexMut<usize> for InputTensors<'i> {
    fn index_mut(&mut self, index: usize) -> &mut Tensor {
        let index = i32::try_from(index).unwrap();
        unsafe {
            &mut *TfLiteInterpreterGetInputTensor(self.interpreter.interpreter.as_ptr(), index)
        }
    }
}

pub struct OutputTensors<'i> {
    interpreter: &'i Interpreter<'i>,
    len: usize,
}

impl<'i> OutputTensors<'i> {
    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'i> std::ops::Index<usize> for OutputTensors<'i> {
    type Output = Tensor;

    fn index(&self, index: usize) -> &Tensor {
        let index = i32::try_from(index).unwrap();
        unsafe { &*TfLiteInterpreterGetOutputTensor(self.interpreter.interpreter.as_ptr(), index) }
    }
}

impl Tensor {
    pub fn type_(&self) -> Type {
        unsafe { TfLiteTensorType(self) }
    }
    pub fn num_dims(&self) -> usize {
        usize::try_from(unsafe { TfLiteTensorNumDims(self) }).unwrap()
    }
    pub fn dim(&self, i: usize) -> usize {
        assert!(i < self.num_dims());
        let i = i32::try_from(i).unwrap();
        usize::try_from(unsafe { TfLiteTensorDim(self, i) }).unwrap()
    }
    pub fn byte_size(&self) -> usize {
        unsafe { TfLiteTensorByteSize(self) }
    }
    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(TfLiteTensorData(self), self.byte_size()) }
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(TfLiteTensorData(self), self.byte_size()) }
    }
    pub fn f32s(&self) -> &[f32] {
        // Tensors are aligned.
        //assert_eq!(self.type_(), Type::Float32);
        let bytes = self.bytes();
        unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const f32, bytes.len() >> 2) }
    }
    pub fn name(&self) -> &str {
        unsafe { CStr::from_ptr(TfLiteTensorName(self)) }
            .to_str()
            .unwrap()
    }
}

impl std::fmt::Debug for Tensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dims = self.num_dims();
        let mut first = true;
        write!(f, "{}: ", self.name())?;
        for i in 0..dims {
            if !first {
                f.write_str("x")?;
            }
            first = false;
            write!(f, "{}", self.dim(i))?;
        }
        write!(f, " {:?}", self.type_())
    }
}

impl std::fmt::Debug for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            /*unsafe { CStr::from_ptr(TfLiteTypeGetName(*self)) }
                .to_str()
                .unwrap(),*/
            "f32"
        )
    }
}

pub struct Delegate {
    delegate: ptr::NonNull<TfLiteDelegate>,
    free: unsafe extern "C" fn(*mut TfLiteDelegate),
}

impl Drop for Delegate {
    fn drop(&mut self) {
        unsafe { (self.free)(self.delegate.as_ptr()) };
    }
}

pub struct Model(ptr::NonNull<TfLiteModel>);

impl Model {
    pub fn from_static(model: &'static [u8]) -> Result<Self, ()> {
        let m = unsafe { TfLiteModelCreate(model.as_ptr(), model.len()) };
        Ok(Model(ptr::NonNull::new(m).ok_or(())?))
    }

    pub fn from_file(filepath: &str) -> Result<Self, ()> {
        let c_str = CString::new(filepath).unwrap().into_raw();
        let m = unsafe { TfLiteModelCreateFromFile(c_str) };
        Ok(Model(ptr::NonNull::new(m).ok_or(())?))
    }
}

impl Drop for Model {
    fn drop(&mut self) {
        unsafe { TfLiteModelDelete(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    pub static MODEL: &'static [u8] =
        include_bytes!("testdata/ssd_mobilenet_v1_coco_2018_01_28.tflite");

    #[test]
    fn create_drop_model() {
        let _m = super::Model::from_static(MODEL).unwrap();
    }

    #[test]
    fn lifecycle() {
        let m = super::Model::from_static(MODEL).unwrap();
        let builder = super::Interpreter::builder();
        let mut interpreter = builder.build(&m).unwrap();
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

    #[cfg(feature = "edgetpu")]
    #[test]
    fn lifecycle_edgetpu() {
        static EDGETPU_MODEL: &'static [u8] = include_bytes!("testdata/edgetpu.tflite");
        let m = super::Model::from_static(EDGETPU_MODEL).unwrap();
        let mut builder = super::Interpreter::builder();
        let devices = super::edgetpu::Devices::list();
        if devices.is_empty() {
            panic!("need an edge tpu installed to run edge tpu tests");
        }
        let delegate = devices[0].create_delegate().unwrap();
        builder.add_owned_delegate(delegate);
        let mut interpreter = builder.build(&m).unwrap();
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
}

