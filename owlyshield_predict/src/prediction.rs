use std::collections::HashMap;
use std::time::SystemTime;

use byteorder::{ByteOrder, LittleEndian};
use moonfire_tflite::*;

use crate::prediction::predmtrx::VecvecCapped;

static MODEL: &'static [u8] = include_bytes!("../models/model.tflite");
static MEANS: &'static [u8] = include_bytes!("../models/mean.json");
static STDVS: &'static [u8] = include_bytes!("../models/std.json");
pub static PREDMTRXCOLS: usize = 25;
pub static PREDMTRXROWS: usize = 200;

pub struct TfLite {
    model: Model,
    means: Vec<f32>,
    stdvs: Vec<f32>,
}

impl TfLite /*<T>*/
/*where T: serde::de::Deserialize<'a> + num::Float*/
{
    pub fn new() -> TfLite {
        let means = serde_json::from_slice(MEANS);
        let stdvs = serde_json::from_slice(STDVS);

        TfLite {
            model: Model::from_static(MODEL).unwrap(),
            means: means.unwrap(),
            stdvs: stdvs.unwrap(),
        }
    }

    pub fn make_prediction(&self, predmtrx: &VecvecCapped<f32>) -> f32 {
        let inputmtrx = self.standardize(predmtrx).to_vec();
        // println!("MEANS: {:?}", self.means);
        // println!("STDVS: {:?}", self.stdvs);
        // println!("NORMALIZED: {:?}", inputmtrx);
        let builder = Interpreter::builder();
        let mut interpreter = builder
            .build(&self.model, predmtrx.rows_len(), PREDMTRXCOLS)
            .unwrap();

        let mut inputs = interpreter.inputs();

        let mut dst = inputs[0].bytes_mut();
        LittleEndian::write_f32_into(inputmtrx.as_slice(), &mut dst);
        interpreter.invoke().unwrap();
        let outputs = interpreter.outputs();

        let y_pred = outputs[0].f32s()[0];
        //println!("YPRED: {}", y_pred);
        y_pred
    }

    fn standardize(&self, predmtrx: &VecvecCapped<f32>) -> VecvecCapped<f32> {
        let mut res = predmtrx.clone();
        let epsilon = 0.0001f32;
        for i in 0..predmtrx.rows_len() {
            //predmtrx.capacity_rows {
            for j in 0..predmtrx.capacity_cols {
                let stdvs_j = self.stdvs[j];
                let denominator = if stdvs_j < epsilon { epsilon } else { stdvs_j };
                res[i][j] = (predmtrx[i][j] - self.means[j]) / denominator
            }
        }
        res
    }
}

pub(crate) type PredictionValues = (SystemTime, usize, f32); //Systime, nombre descripteurs fichiers modifiés, résultat prédiction

#[derive(Debug)]
pub struct Predictions {
    predictions: HashMap<u32, PredictionValues>,
}

impl Predictions {
    pub fn new() -> Predictions {
        Predictions {
            predictions: HashMap::new(),
        }
    }

    pub fn register_prediction(&mut self, now: SystemTime, file_ids_u: usize, pred: f32) {
        let nextidx = self.predictions.keys().max().unwrap_or(&0u32).clone() + 1;
        self.predictions.insert(nextidx, (now, file_ids_u, pred));
    }

    pub fn predictions_count(&self) -> usize {
        self.predictions.len()
    }
}

pub mod predmtrx {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::fmt::{Debug, Display, Formatter};
    use std::ops::{Index, IndexMut};

    use crate::extensions::ExtensionCategory;
    use crate::process::ProcessRecord;

    type Matrix<T> = VecDeque<Vec<T>>;

    #[derive(Debug)]
    pub struct PredictionRow {
        // If you had a field don't forget to increase PREDMTRXCOLS variable
        pub total_ops_r: u64,
        pub total_ops_rn: u64,
        pub total_ops_w: u64,
        pub total_ops_c: u64,
        pub sum_entropy_weight_r: f32,
        pub sum_entropy_weight_w: f32,
        pub extensions_count_r: usize,
        pub extensions_count_w: usize,
        pub file_ids_c_count: usize,
        pub file_ids_d_count: usize,
        pub file_ids_r_count: usize,
        pub file_ids_rn_count: usize,
        pub file_ids_w_count: usize,
        pub file_ids_u_count: usize,
        pub extensions_count_u: usize, //TODO
        pub files_paths_u_count: usize,
        pub pids_count: usize,
        pub extensions_count_w_doc: usize,
        pub extensions_count_w_archives: usize,
        pub extensions_count_w_db: usize,
        pub extensions_count_w_code: usize,
        pub extensions_count_w_exe: usize,
        pub dir_with_files_c_count: usize,
        pub dir_with_files_u_count: usize,
        pub exe_exists: bool,
        pub nb_clusters: usize,
        pub clusters_max_size: usize,
    }

    impl PredictionRow {
        pub fn from(proc: &ProcessRecord) -> PredictionRow {
            PredictionRow {
                total_ops_r: proc.total_ops_r,
                total_ops_rn: proc.total_ops_rn,
                total_ops_w: proc.total_ops_w,
                total_ops_c: proc.total_ops_c,
                sum_entropy_weight_r: Self::order_magnitude(proc.sum_entropy_weight_r) as f32,
                sum_entropy_weight_w: Self::order_magnitude(proc.sum_entropy_weight_w) as f32,
                extensions_count_r: proc.extensions_count_r.count_all(),
                extensions_count_w: proc.extensions_count_w.count_all(),
                file_ids_c_count: proc.file_ids_c.len(),
                file_ids_d_count: proc.file_ids_d.len(),
                file_ids_r_count: proc.file_ids_r.len(),
                file_ids_rn_count: proc.file_ids_rn.len(),
                file_ids_w_count: proc.file_ids_w.len(),
                file_ids_u_count: proc.file_ids_w.len(), //TODO
                extensions_count_u: 0,                   //TODO
                files_paths_u_count: proc.file_paths_u.len(),
                pids_count: proc.pids.len(),
                extensions_count_w_doc: proc
                    .extensions_count_w
                    .count_category(ExtensionCategory::Docs),
                extensions_count_w_archives: proc
                    .extensions_count_w
                    .count_category(ExtensionCategory::Archives),
                extensions_count_w_db: proc
                    .extensions_count_w
                    .count_category(ExtensionCategory::Database),
                extensions_count_w_code: proc
                    .extensions_count_w
                    .count_category(ExtensionCategory::Code),
                extensions_count_w_exe: proc
                    .extensions_count_w
                    .count_category(ExtensionCategory::Exe),
                dir_with_files_c_count: proc.dir_with_files_c.len(),
                dir_with_files_u_count: proc.dir_with_files_u.len(),
                exe_exists: proc.exe_still_exists,
                nb_clusters: proc.nb_clusters,
                clusters_max_size: proc.clusters_max_size,
            }
        }

        pub fn to_vec_f32(&self) -> Vec<f32> {
            let res: Vec<f32> = vec![
                self.total_ops_r as f32,
                self.total_ops_rn as f32,
                self.total_ops_w as f32,
                self.total_ops_c as f32,
                self.sum_entropy_weight_r,
                self.sum_entropy_weight_w,
                self.extensions_count_r as f32,
                self.extensions_count_w as f32,
                self.file_ids_c_count as f32,
                self.file_ids_d_count as f32,
                self.file_ids_r_count as f32,
                self.file_ids_rn_count as f32,
                self.file_ids_w_count as f32,
                // self.file_ids_u_count as f32,
                // self.extensions_count_u as f32,
                self.files_paths_u_count as f32,
                self.pids_count as f32,
                self.extensions_count_w_doc as f32,
                self.extensions_count_w_archives as f32,
                self.extensions_count_w_db as f32,
                self.extensions_count_w_code as f32,
                self.extensions_count_w_exe as f32,
                self.dir_with_files_c_count as f32,
                self.dir_with_files_u_count as f32,
                self.exe_exists as u8 as f32,
                self.nb_clusters as f32,
                self.clusters_max_size as f32,
            ];
            res
        }

        #[inline]
        fn order_magnitude(a: f64) -> u32 {
            if a <= 0f64 {
                0
            } else {
                a.log10() as u32
            }
        }
    }

    pub type VecvecCappedF32 = VecvecCapped<f32>;

    #[derive(Debug, Eq, PartialEq, Clone)]
    pub struct VecvecCapped<T> {
        pub capacity_cols: usize,
        pub capacity_rows: usize,
        elems: Matrix<T>,
    }

    impl<T: Copy + Clone + std::fmt::Debug> VecvecCapped<T> {
        pub fn new(capacity_cols: usize, capacity_rows: usize) -> VecvecCapped<T> {
            VecvecCapped {
                capacity_cols,
                capacity_rows,
                elems: VecDeque::new(),
            }
        }

        pub fn rows_len(&self) -> usize {
            self.elems.len()
        }

        pub fn push_row(&mut self, row: Vec<T>) -> Result<(), VecvecCappedError> {
            if row.len() != self.capacity_cols {
                Result::Err(VecvecCappedError::InvalidRowSize)
            } else {
                if self.elems.len() == self.capacity_rows {
                    self.elems.pop_front();
                }
                self.elems.push_back(row);
                Result::Ok(())
            }
        }

        pub fn to_vec(&self) -> Vec<T> {
            let mut res = Vec::new();
            for v in self.elems.iter() {
                let mut vc = v.clone();
                res.append(&mut vc);
            }
            res
        }
    }

    impl<T> Index<usize> for VecvecCapped<T> {
        type Output = Vec<T>;

        fn index(&self, index: usize) -> &Self::Output {
            &self.elems[index]
        }
    }

    impl<T> IndexMut<usize> for VecvecCapped<T> {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.elems[index]
        }
    }

    #[derive(Debug)]
    pub enum VecvecCappedError {
        InvalidRowSize,
    }

    impl Display for VecvecCappedError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match *self {
                VecvecCappedError::InvalidRowSize => write!(f, "Invalid row size"),
            }
        }
    }

    impl Error for VecvecCappedError {}

    //https://zhauniarovich.com/post/2021/2021-01-testing-errors-in-rust/
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn add_invalid_size_row_should_fail() {
            let mut mtrx = VecvecCapped::new(2, 3);
            let v = vec![1, 2, 3, 4];
            assert!(mtrx.push_row(v).is_err());
        }

        #[test]
        fn add_too_many_rows_should_pop() {
            let mut mtrx = VecvecCapped::new(2, 3);
            let mut ctrl = VecvecCapped::new(2, 3);
            let v1 = vec![1, 2, 3];
            let v2 = vec![3, 4, 5];
            let v3 = vec![6, 7, 8];

            mtrx.push_row(v1.clone()).unwrap();
            mtrx.push_row(v2.clone()).unwrap();
            mtrx.push_row(v3.clone()).unwrap();

            ctrl.push_row(v2.clone()).unwrap();
            ctrl.push_row(v3.clone()).unwrap();

            assert_eq!(mtrx, ctrl);
        }

        #[test]
        fn test_square_bracket_op() {
            let mut mtrx = VecvecCapped::new(3, 2);
            let v1 = vec![1, 2, 3];
            let v2 = vec![3, 4, 5];

            mtrx.push_row(v1).unwrap();
            mtrx.push_row(v2).unwrap();

            assert_eq!(mtrx[1][2], 5);
        }
    }
}
