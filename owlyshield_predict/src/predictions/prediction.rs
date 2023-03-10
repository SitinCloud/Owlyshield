/// Our Input tensor has dimensions *(None, PREDMTRXCOLS)*
pub static PREDMTRXCOLS: usize = 26;
/// We cap the dimension1 of our input tensor (that is the length of the prediction sequence). See
/// [`input_tensors::VecvecCapped`] for details about how and why.
pub static PREDMTRXROWS: usize = 500;

/// Contains structures to transform features computed in [`crate::process::ProcessRecord`] into input tensors.
pub mod input_tensors {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::fmt::{Debug, Display, Formatter};
    use std::ops::{Index, IndexMut};
    use serde::Serialize;

    use crate::extensions::ExtensionCategory;
    use crate::extensions::ExtensionCategory::{Email, Event, PasswordVault};
    use crate::process::ProcessRecord;

    /// Typedef used by [`VecvecCapped`]
    type Matrix<T> = VecDeque<Vec<T>>;

    /// Record of the features used to feed models' inputs tensors.
    /// Features are the results of aggregate functions (mainly *sum*, *max* and *count*) applied to:
    /// 1. Data that comes from the driver (*`ops_read`*, *`entropy_read`*...)
    /// 2. Calculations done in this project [`crate::process`] module (*clustering*)
    #[derive(Debug, Copy, Clone, Serialize)]
    pub struct Timestep {
        /// Count of Read operations [crate::shared_def::IrpMajorOp::IrpRead]
        pub ops_read: u64,
        /// Count of SetInfo operations [crate::shared_def::IrpMajorOp::IrpSetInfo]
        pub ops_setinfo: u64,
        /// Count of Write operations [crate::shared_def::IrpMajorOp::IrpWrite]
        pub ops_written: u64,
        /// Count of Handle Creation operations [crate::shared_def::IrpMajorOp::IrpCreate]
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

        /// Is process altering (reading, writing) email files
        pub alters_email_file: bool,
        /// Number of distinct password vault files read
        pub password_vault_read_count: usize,
        /// Is process altering (reading, writing) Windows log files
        pub alters_event_log_file: bool,
        /// Is process altering (reading, writing) ssh files
        pub alters_ssh_file: bool,
        /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead] on a shared (remote) drive
        pub on_shared_drive_read_count: u32,
        /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite] on a shared (remote) drive
        pub on_shared_drive_write_count: u32,
        /// Count of Read operations [crate::driver_com::IrpMajorOp::IrpRead] on a removable drive
        pub on_removable_drive_read_count: u32,
        /// Count of Write operations [crate::driver_com::IrpMajorOp::IrpWrite] on a removable drive
        pub on_removable_drive_write_count: u32,
        // pub is_web_credentials_read: bool, // TODO
        // pub is_windows_credentials_read: bool, // TODO
    }

    impl Timestep {
        pub fn from(proc: &ProcessRecord) -> Timestep {
            Timestep {
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

                alters_email_file: proc.extensions_read.count_category(Email) > 0
                    || proc.extensions_written.count_category(Email) > 0,
                password_vault_read_count: proc.extensions_read.count_category(PasswordVault),
                alters_event_log_file: proc.extensions_read.count_category(Event) > 0
                    || proc.extensions_written.count_category(Event) > 0,
                alters_ssh_file: proc.fpaths_updated.contains(".ssh"),
                on_shared_drive_read_count: proc.on_shared_drive_read_count,
                on_shared_drive_write_count: proc.on_shared_drive_write_count,
                on_removable_drive_read_count: proc.on_removable_drive_read_count,
                on_removable_drive_write_count: proc.on_removable_drive_write_count,
                // is_web_credentials_read, // TODO
                // is_windows_credentials_read, // TODO
            }
        }

        pub fn to_vec_f32(self) -> Vec<f32> {
            let res: Vec<f32> = vec![
                self.ops_read as f32,
                self.ops_setinfo as f32,
                self.ops_written as f32,
                self.ops_open as f32,
                self.bytes_read as f32,
                self.bytes_written as f32,
                self.entropy_read,
                self.entropy_written,
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
                // (self.alters_email_file as u32) as f32,
                // self.password_vault_read_count as f32,
                // (self.alters_event_log_file as u32) as f32,
                // (self.alters_ssh_file as u32) as f32,
                // self.on_shared_drive_read_count as f32,
                // self.on_shared_drive_write_count as f32,
                // self.on_removable_drive_read_count as f32,
                // self.on_removable_drive_write_count as f32,
                // (self.is_web_credentials_read as u32) as f32, // TODO
                // (self.is_windows_credentials_read as u32) as f32, // TODO
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

    /// Our models inputs take f32 tensors, but [`VecvecCapped`] uses generics.
    pub type VecvecCappedF32 = VecvecCapped<f32>;

    /// A matrix with `fixed_size` to feed the model's input tensors, because too long sequences
    /// (> 1000 steps) would deserve the predictions with RNN, unless tbtt is used.
    ///
    /// For example, with *`capacity_cols`* = 2 and *`capacity_rows`* = 3, after three steps
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

    impl<T: Copy + Clone + Debug> VecvecCapped<T> {
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
                Err(VecvecCappedError::InvalidRowSize)
            } else {
                if self.elems.len() == self.capacity_rows {
                    self.elems.pop_front();
                }
                self.elems.push_back(row);
                Ok(())
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

    /// Any error in `VecvecCapped`.
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

            mtrx.push_row(v1).unwrap();
            mtrx.push_row(v2.clone()).unwrap();
            mtrx.push_row(v3.clone()).unwrap();

            ctrl.push_row(v2).unwrap();
            ctrl.push_row(v3).unwrap();

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
