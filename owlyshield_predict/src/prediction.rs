//! The prediction uses a RNN model (LSTM) trained on a CSV files created by  ```cargo run --features replay```.
//! We use [TensorflowLite](https://www.tensorflow.org/lite/) with the windows dll.
//!
//! This allows us to make predictions locally, without having to install Tensorflow, which is an heavy framework to
//! install and to start.
//! This comes at a price: some interesting features available with Tensorflow and Keras are [not supported
//! by TfLite](https://www.tensorflow.org/lite/convert/rnn). Our main issue is that owlyshield predict
//! can generate very long predictions sequences that could be handle by stateful lstm with trucated
//! backpropagation through time (tbtt). But stateful lstm is not possible with TfLite and the state
//! has to be manually propagated between epochs. That's why we limit the sequence length, capped to
//! [PREDMTRXROWS]. See module [input_tensors] for details.

use std::collections::HashMap;
use std::time::SystemTime;

use byteorder::{ByteOrder, LittleEndian};
use moonfire_tflite::*;

use crate::prediction::input_tensors::VecvecCapped;

/// The .tflite (converted from Tensorflow/Keras) model is included as a static variable.
static MODEL: &'static [u8] = include_bytes!("../models/model.tflite");
/// Features means vector, used by Standard Scaling.
static MEANS: &'static [u8] = include_bytes!("../models/mean.json");
/// Features standard deviations vector used by Standard Scaling.
static STDVS: &'static [u8] = include_bytes!("../models/std.json");

/// Our Input tensor has dimensions *(None, PREDMTRXCOLS)*
pub static PREDMTRXCOLS: usize = 26;
/// We cap the dimension1 of our input tensor (that is the length of the prediction sequence). See
/// [VecvecCapped] for details about how and why.
pub static PREDMTRXROWS: usize = 500;

/// A record to describe a tflite model
pub struct TfLite {
    model: Model,
    /// Needed by Standard Scaling and set to [MEANS]
    means: Vec<f32>,
    /// Needed by Standard Scaling and set to [STDVS]
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

    /// Make a prediction on the sequence *predmtrx*. The prediction can be costly.
    /// The model input tensor dimensions are (None, [PREDMTRXCOLS]) and is dimensioned accordingly
    /// by the *InterpreterBuilder*.
    /// The model returns only the last prediction (it does not returns sequences).
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

    /// Standard Scaling of the input vectors with [MEANS] and [STDVS].
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

/// A record to maintain a history of past predictions. Values are
/// (moment of prediction, how many fids with update //TODO, the prediction result)
pub(crate) type PredictionValues = (SystemTime, usize, f32);

/// Manage the histoy of predictions, used to decide when to predict by [crate::process::ProcessRecord::is_to_predict].
#[derive(Debug)]
pub struct Predictions {
    /// History of predictions. The key is the iterator in range(how many predictions).
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

    pub fn get_last_prediction(&self) -> Option<f32> {
        let map_len = self.predictions_count() as u32;
        if map_len == 0 {
            None
        } else {
            Some(self.predictions[&(map_len-1)].2)
        }
    }
}

/// Contains structures to connect a [crate::process::ProcessRecord] with a [TfLite] input tensor.
pub mod input_tensors {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::fmt::{Debug, Display, Formatter};
    use std::ops::{Index, IndexMut};

    use crate::extensions::ExtensionCategory;
    use crate::process::ProcessRecord;

    /// Typedef used by [VecvecCapped]
    type Matrix<T> = VecDeque<Vec<T>>;

    /// Record of the features used to feed the input tensor with [super::TfLite::make_prediction].
    /// Features are the results of aggregate functions (mainly *sum*, *max* and *count*) applied to:
    /// 1. Data that comes from the driver (*ops_read*, *entropy_read*...)
    /// 2. Calculations done in this project [crate::process] module (*clustering*)
    #[derive(Debug)]
    pub struct PredictionRow {
        /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead]
        pub ops_read: u64,
        /// Count of SetInfo operations [crate::driver_com::IrpMajorOp::IrpSetInfo]
        pub ops_setinfo: u64,
        /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite]
        pub ops_written: u64,
        /// Count of Handle Creation operations [crate::driver_com::IrpMajorOp::IrpCreate]
        pub ops_open: u64,
        /// Total bytes read (by gid)
        pub bytes_read: u64,
        /// Total bytes written (by gid)
        pub bytes_written: u64,
        /// Total entropy read
        pub entropy_read: f32,
        /// Total entropy write
        pub entropy_written: f32,
        /// File descriptors created
        pub files_opened: usize,
        /// File descriptors deleted
        pub files_deleted: usize,
        /// File descriptors read
        pub files_read: usize,
        /// File descriptors renamed
        pub files_renamed: usize,
        /// File descriptors written
        pub files_written: usize,
        /// Unique extensions read count
        pub extensions_read: usize,
        /// Unique extensions write count
        pub extensions_written: usize,
        /// Unique extensions written count (documents)
        pub extensions_written_doc: usize,
        /// Unique extensions written count (archives)
        pub extensions_written_archives: usize,
        /// Unique extensions written count (DB)
        pub extensions_written_db: usize,
        /// Unique extensions written count (code)
        pub extensions_written_code: usize,
        /// Unique extensions written count (executables)
        pub extensions_written_exe: usize,
        /// Directories having files created
        pub dirs_with_files_created: usize,
        /// Directories having files updated
        pub dirs_with_files_updated: usize,
        /// Number of pids in this gid process family
        pub pids: usize,
        /// Process exe file still exists (father)?
        pub exe_exists: bool,
        /// Number of directories (with files updated) clusters created
        pub clusters: usize,
        /// Deepest cluster size
        pub clusters_max_size: usize,
    }

    impl PredictionRow {
        pub fn from(proc: &ProcessRecord) -> PredictionRow {
            PredictionRow {
                bytes_read: proc.bytes_read,
                bytes_written: proc.bytes_written,
                ops_read: proc.ops_read,
                ops_setinfo: proc.ops_setinfo,
                ops_written: proc.ops_written,
                ops_open: proc.ops_open,
                entropy_read: Self::order_magnitude(proc.entropy_read) as f32,
                entropy_written: Self::order_magnitude(proc.entropy_written) as f32,
                extensions_read: proc.extensions_read.count_all(),
                extensions_written: proc.extensions_written.count_all(),
                files_opened: proc.files_opened.len(),
                files_deleted: proc.files_deleted.len(),
                files_read: proc.files_read.len(),
                files_renamed: proc.files_renamed.len(),
                files_written: proc.files_written.len(),
                pids: proc.pids.len(),
                extensions_written_doc: proc
                    .extensions_written
                    .count_category(ExtensionCategory::Docs),
                extensions_written_archives: proc
                    .extensions_written
                    .count_category(ExtensionCategory::Archives),
                extensions_written_db: proc
                    .extensions_written
                    .count_category(ExtensionCategory::Database),
                extensions_written_code: proc
                    .extensions_written
                    .count_category(ExtensionCategory::Code),
                extensions_written_exe: proc
                    .extensions_written
                    .count_category(ExtensionCategory::Exe),
                dirs_with_files_created: proc.dirs_with_files_created.len(),
                dirs_with_files_updated: proc.dirs_with_files_updated.len(),
                exe_exists: proc.exe_exists,
                clusters: proc.clusters,
                clusters_max_size: proc.clusters_max_size,
            }
        }

        pub fn to_vec_f32(&self) -> Vec<f32> {
            let res: Vec<f32> = vec![
                self.ops_read as f32,
                self.ops_setinfo as f32,
                self.ops_written as f32,
                self.ops_open as f32,
                self.bytes_read as f32,
                self.bytes_written as f32,
                self.entropy_read as f32,
                self.entropy_written as f32,
                self.files_opened as f32,
                self.files_deleted as f32,
                self.files_read as f32,
                self.files_renamed as f32,
                self.files_written as f32,
                self.extensions_read as f32,
                self.extensions_written as f32,
                self.extensions_written_doc as f32,
                self.extensions_written_archives as f32,
                self.extensions_written_db as f32,
                self.extensions_written_code as f32,
                self.extensions_written_exe as f32,
                self.dirs_with_files_created as f32,
                self.dirs_with_files_updated as f32,
                self.pids as f32,
                self.exe_exists as u8 as f32,
                self.clusters as f32,
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

    /// Our [super::TfLite] model waits for f32, but [VecvecCapped] uses generics.
    pub type VecvecCappedF32 = VecvecCapped<f32>;

    /// A matrix with fixed_size to feed the model's input tensors, because too long sequences
    /// (> 1000 steps) would deserve the predictions with RNN, unless tbtt is used.
    ///
    /// For example, with *capacity_cols* = 2 and *capacity_rows* = 3, after three steps
    ///
    /// | Timestep | Feature 1 | Feature 2 |
    /// |:----:|:---------:|:---------:|
    /// | 1    | a1        | b1        |
    /// | 2    | a2        | b2        |
    /// | 3    | a3        | b3        |
    ///
    /// Then after a fourth step was added:
    ///
    /// | Timestep | Feature 1 | Feature 2 |
    /// |:----:|:---------:|:---------:|
    /// | 2    | a2        | b2        |
    /// | 3    | a3        | b3        |
    /// | 4    | a4        | b4        |
    ///
    #[derive(Debug, Eq, PartialEq, Clone)]
    pub struct VecvecCapped<T> {
        /// Number of features, equivalent to input_tensor.dim\[1\]
        pub capacity_cols: usize,
        /// Max number of timesteps.
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

    /// Any error in VecvecCapped.
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
            let mut mtrx = VecvecCapped::new(3, 2);
            let mut ctrl = VecvecCapped::new(3, 2);
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
