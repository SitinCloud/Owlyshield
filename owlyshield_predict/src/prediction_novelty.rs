use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::ops::Index;
use std::path::Path;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use moonfire_tflite::{Interpreter, Model};
use num_traits::real::Real;
use num_traits::ToPrimitive;
use serde::de::Expected;
use win_pe_inspection::LibImport;
use crate::prediction::input_tensors::{VecvecCapped, VecvecCappedF32};
use crate::prediction::PREDMTRXCOLS;


// /// The .tflite (converted from Tensorflow/Keras) model is included as a static variable.
// static MODEL: &'static [u8] = include_bytes!("../models/model_novelty.tflite");
// /// Features means vector, used by Standard Scaling.
// static DATA_MIN: &'static [u8] = include_bytes!("../models/data_min_novelty.json");
// /// Features standard deviations vector used by Standard Scaling.
// static DATA_MAX: &'static [u8] = include_bytes!("../models/data_max_novelty.json");

static MODELS: &str = "./models/novelty";
static THRESHOLDS: &str = "./models/threshold.json";

pub struct TfLiteNovelty {
    // model: Model,
    // /// Needed by Standard Scaling and set to [MEANS]
    // data_min: Vec<f32>,
    // /// Needed by Standard Scaling and set to [STDVS]
    // data_max: Vec<f32>,

    models: HashMap<String, Model>,
    data_mins: HashMap<String, Vec<f32>>,
    data_maxs: HashMap<String, Vec<f32>>,

    thresholds: HashMap<String, f32>,
}

impl TfLiteNovelty {
    pub fn new() -> TfLiteNovelty {
        let dir_models = Path::new(MODELS).read_dir().expect("read_dir call failed.");

        let mut models : HashMap<String, Model> = Default::default();
        let mut data_mins : HashMap<String, Vec<f32>> = Default::default();
        let mut data_maxs : HashMap<String, Vec<f32>> = Default::default();

        for entry in dir_models {
            if let Ok(entry) = entry {
                let fname = entry.file_name().to_str().unwrap().to_string();
                let fpath = entry.path().to_str().unwrap().to_string();

                let mut content = Vec::new();
                BufReader::new(File::open(fpath).unwrap()).read_to_end(&mut content).unwrap();

                if fname.starts_with("model_") {
                    let appname = fname[6..fname.rfind("_").unwrap()].replace("_",".");
                    models.insert(appname, Model::from_file( entry.path().to_str().unwrap()).unwrap());
                } else if fname.starts_with("data_min_") {
                    let appname = fname[9..fname.rfind("_").unwrap()].replace("_",".");
                    data_mins.insert(appname, serde_json::from_slice(content.as_slice()).unwrap());
                } else if fname.starts_with("data_max_") {
                    let appname = fname[9..fname.rfind("_").unwrap()].replace("_",".");
                    data_maxs.insert(appname, serde_json::from_slice(content.as_slice()).unwrap());
                }
            }
        }

        let mut t = Vec::new();
        let mut thresholds = HashMap::new();
        if Path::new(THRESHOLDS).exists() {
            BufReader::new(File::open(THRESHOLDS).unwrap()).read_to_end(&mut t).unwrap();
            thresholds = serde_json::from_slice(t.as_slice()).unwrap();
        }

        TfLiteNovelty {
            models: models,
            data_mins: data_mins,
            data_maxs: data_maxs,
            thresholds: thresholds,
        }
    }

    pub fn get_threshold_value(&self, appname: &str) -> Option<f32> {
        let t = self.thresholds.get_key_value(appname);
        if t.is_some() {
            return Some(t.unwrap().1.to_f32().unwrap())
        }
        None
    }

    pub fn make_prediction(&self, predmtrx: &VecvecCapped<f32>, appname: &str) -> f32 {
        if self.models.get(appname).is_none() || self.data_mins.get(appname).is_none() || self.data_maxs.get(appname).is_none() {
            println!("sortie");
            return 0f32
        }

        let model = self.models.get(appname).unwrap();
        let data_min = self.data_mins.get(appname).unwrap();
        let data_max = self.data_maxs.get(appname).unwrap();

        let inputmtrx = self.standardize(predmtrx, data_min, data_max).to_vec();
        // println!("MIN: {:?}", data_min);
        // println!("MAX: {:?}", data_max);
        // println!("NORMALIZED: {:?}", inputmtrx);
        let builder = Interpreter::builder();
        let mut interpreter = builder
            .build(&model, predmtrx.rows_len(), PREDMTRXCOLS)
            .unwrap();

        let mut inputs = interpreter.inputs();

        let mut dst = inputs[0].bytes_mut();
        LittleEndian::write_f32_into(inputmtrx.as_slice(), &mut dst);
        let mut inputmtrx2 : VecvecCapped<f32> = VecvecCapped::new(predmtrx.capacity_cols, predmtrx.capacity_rows);
        for i in 0..predmtrx.rows_len() { //20 { //outputs.len() { //Taille matrice apprentissage ?
            let mut y = Vec::new();
            for j in 0..predmtrx.capacity_cols {
                y.push(inputs[0].f32s()[(i * predmtrx.capacity_cols) + j]);
            }
            inputmtrx2.push_row(y).unwrap();
        }

        let mut dst = inputs[0].bytes_mut();
        LittleEndian::write_f32_into(inputmtrx.as_slice(), &mut dst);
        interpreter.invoke().unwrap();

        let outputs = interpreter.outputs();

        let mut outputmtrx : VecvecCapped<f32> = VecvecCapped::new(predmtrx.capacity_cols, predmtrx.capacity_rows);
        for i in 0..predmtrx.rows_len() { //20 { //outputs.len() { //Taille matrice apprentissage ?
            let mut y = Vec::new();
            for j in 0..predmtrx.capacity_cols {
                y.push(outputs[0].f32s()[(i * predmtrx.capacity_cols) + j]);
            }
            outputmtrx.push_row(y).unwrap();
        }

        let output = VecvecCappedF32::mse(&outputmtrx, &inputmtrx2);
        //println!("YPRED: {}", output.iter().sum());
        output.iter().sum()
    }

    // scaling
    fn standardize(&self, predmtrx: &VecvecCapped<f32>, data_min: &Vec<f32>, data_max: &Vec<f32>) -> VecvecCapped<f32> {
        // dbg!(predmtrx.rows_len());
        let mut res = predmtrx.clone();
        let epsilon = 0.001f32;
        for i in 0..predmtrx.rows_len() {
            //predmtrx.capacity_rows {
            // for j in 0..predmtrx.capacity_cols {
            for j in 0..data_max.len() {
                let denominator = data_max[j] - data_min[j];
                if denominator == 0f32 {
                    res[i][j] = predmtrx[i][j];
                } else {
                    res[i][j] = (predmtrx[i][j] - data_min[j]) / denominator;
                }
            }
        }
        res
    }
}
