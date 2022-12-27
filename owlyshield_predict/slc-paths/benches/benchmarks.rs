use criterion::{black_box, criterion_group, criterion_main, Criterion};
use slc_paths::clustering::clustering_from_file;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("test_tor_file", |b| {
        b.iter(|| {
            let nom_fichier = r".\testdata\tor.txt";
            let clusters = clustering_from_file(black_box(nom_fichier));
            assert!(!clusters.is_empty());
            assert_eq!(clusters.iter().map(|c| c.size()).sum::<usize>(), 17);
        })
    });

    c.bench_function("test_eclipse_file", |b| {
        b.iter(|| {
            // let start = Instant::now();
            let nom_fichier = r".\testdata\eclipse.txt";
            let clusters = clustering_from_file(black_box(nom_fichier));
            assert!(clusters.iter().any(|c| c.root() == r"C:\Users\lesco"));
            assert_eq!(clusters.len(), 3);
            assert_eq!(clusters.iter().map(|p| p.size()).max().unwrap_or(0), 16);
            // for c in clusters {
            //     println!("Step {} : Taille = {} : Root = {}", c.step(), c.size(), c.root());
            // }
            // println!("Durée : {:?}",start.elapsed());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
