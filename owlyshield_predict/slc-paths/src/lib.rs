pub mod clustering {
    use std::path::Path;
    use std::cmp;
    use kodama::{Method, linkage};
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::collections::HashSet;

    pub struct Cluster {
        root : String,
        size: usize,
        step: usize,
    }

    impl Cluster {
        pub fn root(&self) -> String {
            self.root.clone()
        }

        pub fn size(&self) -> usize {
            self.size
        }

        pub fn step(&self) -> usize {
            self.step
        }
    }

    pub fn clustering_from_file(filename: &str) -> Vec<Cluster> {
        let mut strpaths: HashSet<String> = HashSet::new();
        let file = File::open(filename).unwrap();
        let lines = BufReader::new(&file).lines();

        for line in lines {
            strpaths.insert(line.unwrap());
        }
        return clustering(strpaths);
    }

    pub fn clustering(strpaths: HashSet<String>) -> Vec<Cluster> {

        if strpaths.len() == 0 {
            return vec![];
        }

        let paths: Vec<&Path> = strpaths.iter().map(|s| Path::new(s)).collect();

        if paths.len() == 1 {
            return vec![Cluster {
                root: paths[0].to_string_lossy().to_string(),
                size: 1,
                step: 0
            }];
        }

        if paths.len() == 2 {
            return if paths[0].as_os_str() == paths[1].as_os_str() {
                vec![Cluster {
                    root: paths[0].to_string_lossy().to_string(),
                    size: 2,
                    step: 0
                }]
            } else {
                vec![Cluster {
                    root: paths[0].to_string_lossy().to_string(),
                    size: 1,
                    step: 0
                }, Cluster {
                    root: paths[1].to_string_lossy().to_string(),
                    size: 1,
                    step: 0
                }]
            }
        }

        let mut condensed = vec![];
        let mut clusters_paths = vec![];

        for i in 0..paths.len() - 1 {
            for j in i + 1..paths.len() {
                condensed.push(distance(paths[j], paths[i]));
            }
            clusters_paths.push(paths[i].to_string_lossy().to_string());//.to_str().unwrap().to_string());
        }
        clusters_paths.push( paths[paths.len()-1].to_string_lossy().to_string());

        let dendogram = linkage(&mut condensed, paths.len(), Method::Single);

        for dend_step in dendogram.steps().iter() {
            let cluster1_dirs: Vec<&str> = clusters_paths[dend_step.cluster1].split(r"\").collect();
            let cluster2_dirs: Vec<&str> = clusters_paths[dend_step.cluster2].split(r"\").collect();
            let min_file_depth = cmp::min(cluster1_dirs.len(), cluster2_dirs.len());

            let mut cur_file_depth = 0;
            let mut common_filepath = ".".to_owned();

            while cur_file_depth < min_file_depth {
                if cluster1_dirs[cur_file_depth] == cluster2_dirs[cur_file_depth] {
                    common_filepath.push_str(r"\");
                    common_filepath.push_str(cluster1_dirs[cur_file_depth]);
                } else {
                    break;
                }
                cur_file_depth += 1;
            }
            if common_filepath.len() > 2 {
                //remove .\
                common_filepath.remove(0);
                common_filepath.remove(0);
            }
            clusters_paths.push(common_filepath);
        }

        let mut max_point = 0usize;
        let mut max_diff = dendogram.steps()[1].dissimilarity - dendogram.steps()[0].dissimilarity;

        // for i in 0..paths.len()+2 {
        //     println!("  ({}) : {}", i, clusters_paths[i]);
        // }

        for i in 2..dendogram.len() {
            // println!("{} ({}) : {} | {} | {} | {} | {}",
            //          i,
            //          i + paths.len(),
            //          dendogram.steps()[i].cluster1,
            //          dendogram.steps()[i].cluster2,
            //          dendogram.steps()[i].dissimilarity,
            //          dendogram.steps()[i].size,
            //          clusters_paths[i + paths.len()],
            // );
            if dendogram.steps()[i].dissimilarity - dendogram.steps()[i-1].dissimilarity > max_diff //as f32
            {
                max_diff = dendogram.steps()[i].dissimilarity - dendogram.steps()[i-1].dissimilarity;
                max_point = i;
            }
        }

        let mut clusters = vec![];
        for i in max_point..clusters_paths.len()-paths.len() {
            let index_cluster1 = dendogram.steps()[i].cluster1;
            let index_cluster2 = dendogram.steps()[i].cluster2;
            if index_cluster1 < max_point+paths.len() {
                clusters.push(
                    Cluster {
                        root: clusters_paths[index_cluster1].clone(),
                        size: if index_cluster1 > paths.len() { dendogram.steps()[index_cluster1 - paths.len()].size } else { 1 },
                        step: i,
                    }
                );
            }
            if  index_cluster2 < max_point+paths.len() {
                clusters.push(
                    Cluster {
                        root: clusters_paths[index_cluster2].clone(),
                        size: if index_cluster2 > paths.len() { dendogram.steps()[index_cluster2 - paths.len()].size } else { 1 },
                        step: i,
                    }
                );
            }
        }
        return clusters;
    }

    pub fn distance(x: &Path, y: &Path) -> f32 {
        if x.as_os_str() == y.as_os_str() {
            return 0.0; //Même fichier
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

        while path1 != None {
            if path1.unwrap().as_os_str() == path2.unwrap().as_os_str() {
                return dist;
            } else {
                path1 = path1.unwrap().parent();
                dist += 1.0;
            }
        }

        //path1 & path2 are on different root disk
        while path2 != None {
            path2 = path2.unwrap().parent();
            dist += 1.0;
        }
        return dist;
    }
}

#[cfg(test)]
mod tests {
    // use crate::clustering::clustering;
    use crate::clustering::clustering_from_file;
    // use std::time::Instant;

    #[test]
    fn test_tor_file() {
        let nom_fichier = r".\src\testdata\tor.txt";
        let clusters = clustering_from_file(nom_fichier);
        assert!(!clusters.is_empty());
        assert_eq!(clusters.iter().map(|c| c.size()).sum::<usize>(), 17);
    }

    #[test]
    fn test_eclipse_file() {
        // let start = Instant::now();
        let nom_fichier = r".\src\testdata\eclipse.txt";
        let clusters = clustering_from_file(nom_fichier);
        assert!(clusters.iter().any(|c| c.root() == r"C:\Users\lesco"));
        assert_eq!(clusters.len(), 4);
        assert_eq!(clusters.iter().map(|p| p.size()).max().unwrap_or(0), 15);
        // for c in clusters {
        //     println!("Step {} : Taille = {} : Root = {}", c.step(), c.size(), c.root());
        // }
        // println!("Durée : {:?}",start.elapsed());
    }
}
