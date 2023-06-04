//!! # slc-path
//!
//! `slc-path` crate is based on the [`single-linkage_clustering`](https://!en.wikipedia.org/wiki/Single-linkage_clustering)
//! method. In statistics, single-linkage clustering is one of several methods of hierarchical clustering.
//!
//! This method tends to produce long thin clusters in which nearby elements of the same cluster have small distances, but
//! elements at opposite ends of a cluster may be much farther from each other than two elements of other clusters. For some
//! classes of data, this may lead to difficulties in defining classes that could usefully subdivide the data. However,
//! it is popular in astronomy for analyzing galaxy clusters, which may often involve long strings of matter; in this
//! application, it is also known as the friends-of-friends algorithm.
//!
//! It is based on grouping clusters in bottom-up fashion (agglomerate clustering), at each step
//! combining two clusters that contain the closest pair of elements not yet belonging to the same
//! cluster as each other.
//!
//! This module principally use the [`kodama`](https://!docs.rs/kodama/latest/kodama/) crate. With a
//! [forked](https://!github.com/SubconsciousCompute/kodama) version.
//!
//! Clustering allows to trace the extent of the impact of a program on the file tree.
//!
//! # Working Example
//!
//! ## First step
//!
//! ### First clustering
//!
//! Let us assume that we have five elements `(a,b,c,d,e)` and the following matrix `D1` of pairwise
//! distances between them:
//!
//! |          | a    | b    | c   | d   | e   |
//! |----------|------|------|-----|-----|-----|
//! | <b>a</b> | 0    | `17` | 21  | 31  | 23  |
//! | <b>b</b> | `17` | 0    | 30  | 34  | 21  |
//! | <b>c</b> | 21   | 30   | 0   | 28  | 39  |
//! | <b>d</b> | 31   | 34   | 28  | 0   | 43  |
//! | <b>e</b> | 23   | 21   | 39  | 43  | 0   |
//!
//! In this example, `D1(a,b)=17` is the lowest value of `D1`, so we cluster elements `a` and `b`.
//!
//! ### First distance matrix update
//!
//! We then proceed to update the initial proximity matrix `D1` into a new proximity matrix `D2`
//! (see below), reduced in size by one row and one column because of the clustering of `a` with `b`.
//! Bold values in `D2` correspond to the new distances, calculated by retaining the minimum distance
//! between each element of the first cluster `(a,b)` and each of the remaining elements:
//!
//! ```ignore
//! D2((a,b),c)=min(D1(a,c),D1(b,c))=min(21,30)=21
//! D2((a,b),d)=min(D1(a,d),D1(b,d))=min(31,34)=31
//! D2((a,b),e)=min(D1(a,e),D1(b,e))=min(23,21)=21
//! ```
//!
//! Italicized values in `D2` are not affected by the matrix update as they correspond to distances
//! between elements not involved in the first cluster.
//!
//! ## Second step
//!
//! ### Second clustering
//!
//! We now reiterate the three previous actions, starting from the new distance matrix `D2`:
//!
//! |              | (a,b)       | c           | d         | e           |
//! |--------------|-------------|-------------|-----------|-------------|
//! | <b>(a,b)</b> | 0           | <b>`21`</b> | <b>31</b> | <b>`21`</b> |
//! | <b>c</b>     | <b>`21`</b> | 0           | 28        | 39          |
//! | <b>d</b>     | <b>31</b>   | 28          | 0         | 43          |
//! | <b>e</b>     | <b>`21`</b> | 39          | 43        | 0           |
//!
//! Here, `D2((a,b),c)=21` and `D2((a,b),e)=21` are the lowest values of `D2`, so we join cluster `(a,b)`
//! with element `c` and with element `e`.
//!
//! ### Second distance matrix update
//!
//! We then proceed to update the `D2` matrix into a new distance matrix `D3` (see below), reduced in
//! size by two rows and two columns because of the clustering of `(a,b)` with `c` and with `e`:
//!
//! `D3(((a,b),c,e),d)=min(D2((a,b),d),D2(c,d),D2(e,d))=min(31,28,43)=28`
//!
//! ## Final step
//!
//! The final `D3` matrix is:
//!
//! |                    | ((a,b),c,e) | d           |
//! |--------------------|-------------|-------------|
//! | <b>((a,b),c,e)</b> | 0           | <b>`28`</b> |
//! | <b>d</b>           | <b>`28`</b> | 0           |
//!
//! So we join clusters `((a,b),c,e)` and `d`.
//! Let `r` denote the `(root)` node to which `((a,b),c,e)` and `d` are now connected.
//!
//! ## The single-linkage dendrogram
//!
//! ![Single Linkage Dendrogram 5S data](https://upload.wikimedia.org/wikipedia/commons/thumb/4/43/Simple_linkage-5S.svg/600px-Simple_linkage-5S.svg.png)
//!
//! The dendrogram is now complete. It is ultrametric because all tips `(a,b,c,e, and d)` are equidistant from `r`:
//!
//! `δ(a,r) = δ(b,r) = δ(c,r) = δ(e,r) = δ(d,r) = 14`
//!
//! The dendrogram is therefore rooted by `r`, its deepest node.

/// This module manages clusters generated from filepath lists.
pub mod clustering {
    use kodama::{linkage, Method};
    use std::cmp;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::path::Path;
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Cluster {
        pub root: String,
        pub size: usize,
        pub step: usize,
    }

    pub type Clusters = Vec<Cluster>;

    impl Cluster {
        /// Returns the common root of the cluster files.
        #[must_use]
        pub fn root(&self) -> String {
            self.root.clone()
        }
        /// Returns the number of files in the cluster.
        #[must_use]
        pub fn size(&self) -> usize {
            self.size
        }
        /// Returns the step where the cluster was created.
        #[must_use]
        pub fn step(&self) -> usize {
            self.step
        }
    }

    /// Returns the list of [Cluster] from a file containing a list of filepaths.
    /// This function calls the [clustering] function.
    #[must_use]
    pub fn clustering_from_file(filename: &str) -> Clusters {
        let mut strpaths: HashSet<String> = HashSet::new();
        let file = File::open(filename).unwrap();
        let lines = BufReader::new(&file).lines();

        for line in lines {
            strpaths.insert(line.unwrap());
        }
        clustering(&strpaths)
    }

    /// Returns the list of [Cluster] from a list of filepaths.
    /// It builds a dendrogram from the input list and analyzes it to return a list of clusters.
    /// The returned list is the list of clusters just before the moment where the dissimilarity
    /// between 2 successive steps is the greatest.
    ///
    /// There are 2 cases where the behavior is different :
    /// If the input list is empty, it will return an empty list
    /// If the input list contains less than 3 elements, it will return as many clusters as there
    /// are filepaths in input
    #[must_use]
    pub fn clustering<S: std::hash::BuildHasher>(strpaths: &HashSet<String, S>) -> Clusters {
        if strpaths.is_empty() {
            return vec![];
        }

        let paths: Vec<&Path> = strpaths.iter().map(Path::new).collect();

        if paths.len() == 1 {
            return vec![Cluster {
                root: paths[0].to_string_lossy().to_string(),
                size: 1,
                step: 0,
            }];
        }

        if paths.len() == 2 {
            return if paths[0].as_os_str() == paths[1].as_os_str() {
                vec![Cluster {
                    root: paths[0].to_string_lossy().to_string(),
                    size: 2,
                    step: 0,
                }]
            } else {
                vec![
                    Cluster {
                        root: paths[0].to_string_lossy().to_string(),
                        size: 1,
                        step: 0,
                    },
                    Cluster {
                        root: paths[1].to_string_lossy().to_string(),
                        size: 1,
                        step: 0,
                    },
                ]
            };
        }

        let mut condensed = vec![];
        let mut clusters_paths = vec![];

        for i in 0..paths.len() - 1 {
            for j in i + 1..paths.len() {
                condensed.push(distance(paths[j], paths[i]));
            }
            clusters_paths.push(paths[i].to_string_lossy().to_string());
        }
        clusters_paths.push(paths[paths.len() - 1].to_string_lossy().to_string());

        let dendrogram = linkage(&mut condensed, paths.len(), Method::Single);

        for dend_step in dendrogram.steps().iter() {
            let cluster1_dirs: Vec<&str> = clusters_paths[dend_step.cluster1].split('\\').collect();
            let cluster2_dirs: Vec<&str> = clusters_paths[dend_step.cluster2].split('\\').collect();
            let min_file_depth = cmp::min(cluster1_dirs.len(), cluster2_dirs.len());

            let mut cur_file_depth = 0;
            let mut common_filepath = ".".to_owned();

            while cur_file_depth < min_file_depth {
                if cluster1_dirs[cur_file_depth] == cluster2_dirs[cur_file_depth] {
                    common_filepath.push('\\');
                    common_filepath.push_str(cluster1_dirs[cur_file_depth]);
                } else {
                    break;
                }
                cur_file_depth += 1;
            }
            if common_filepath.len() > 2 {
                // remove .\
                common_filepath.remove(0);
                common_filepath.remove(0);
            }
            clusters_paths.push(common_filepath);
        }

        let mut max_point = 0usize;
        let mut max_diff =
            dendrogram.steps()[1].dissimilarity - dendrogram.steps()[0].dissimilarity;

        // for i in 0..paths.len()+2 {
        //     println!("  ({}) : {}", i, clusters_paths[i]);
        // }

        for i in 2..dendrogram.len() {
            // println!("{} ({}) : {} | {} | {} | {} | {}",
            //          i,
            //          i + paths.len(),
            //          dendrogram.steps()[i].cluster1,
            //          dendrogram.steps()[i].cluster2,
            //          dendrogram.steps()[i].dissimilarity,
            //          dendrogram.steps()[i].size,
            //          clusters_paths[i + paths.len()],
            // );
            if dendrogram.steps()[i].dissimilarity - dendrogram.steps()[i - 1].dissimilarity
                > max_diff
            //as f32
            {
                max_diff =
                    dendrogram.steps()[i].dissimilarity - dendrogram.steps()[i - 1].dissimilarity;
                max_point = i;
            }
        }

        let mut clusters = vec![];
        for i in max_point..clusters_paths.len() - paths.len() {
            let index_cluster1 = dendrogram.steps()[i].cluster1;
            let index_cluster2 = dendrogram.steps()[i].cluster2;

            macro_rules! cluster_entry {
                ($index_cluster: expr) => {
                    if $index_cluster < max_point + paths.len() {
                        clusters.push(Cluster {
                            root: clusters_paths[$index_cluster].clone(),
                            size: if $index_cluster > paths.len() {
                                dendrogram.steps()[$index_cluster - paths.len()].size
                            } else {
                                1
                            },
                            step: i,
                        });
                    }
                };
            }

            cluster_entry!(index_cluster1);
            cluster_entry!(index_cluster2);
        }
        clusters
    }

    /// Returns the distance between 2 files in the file tree.
    #[must_use]
    pub fn distance(x: &Path, y: &Path) -> f32 {
        if x.as_os_str() == y.as_os_str() {
            return 0.0; // Same file
        }

        let depth_x = x.ancestors().count();
        let depth_y = y.ancestors().count();
        let mut path1;
        let mut path2;
        let mut dist = 1.0;

        if depth_x > depth_y {
            path1 = x.parent();
            path2 = y.parent();
        } else {
            path1 = y.parent();
            path2 = x.parent();
        }

        while path1.is_some() {
            if path2.is_none() {
                path1 = path1.unwrap().parent();
                dist += 1.0;
            } else if path1.unwrap().as_os_str() == path2.unwrap().as_os_str() {
                return dist;
            } else {
                path1 = path1.unwrap().parent();
                dist += 1.0;
            }
        }

        // path1 & path2 are on different root disk
        while path2.is_some() {
            path2 = path2.unwrap().parent();
            dist += 1.0;
        }
        dist * dist
    }
}
