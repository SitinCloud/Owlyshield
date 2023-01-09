use slc_paths::clustering::clustering_from_file;

// use std::time::Instant;

#[test]
fn test_tor_file() {
    let nom_fichier = r".\testdata\tor.txt";
    let clusters = clustering_from_file(nom_fichier);
    assert!(!clusters.is_empty());
    assert_eq!(clusters.iter().map(|c| c.size()).sum::<usize>(), 17);
}

#[test]
fn test_eclipse_file() {
    // let start = Instant::now();
    let nom_fichier = r".\testdata\eclipse.txt";
    let clusters = clustering_from_file(nom_fichier);
    assert!(clusters.iter().any(|c| c.root() == r"C:\Users\sn99"));
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters.iter().map(|p| p.size()).max().unwrap_or(0), 16);
    // for c in clusters {
    //     println!("Step {} : Taille = {} : Root = {}", c.step(), c.size(), c.root());
    // }
    // println!("Durée : {:?}",start.elapsed());
}
