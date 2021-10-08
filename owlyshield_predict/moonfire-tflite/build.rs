// Copyright (C) 2020 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::Path;

//https://stackoverflow.com/questions/41917096/how-do-i-make-rustc-link-search-relative-to-the-project-location
//https://doc.rust-lang.org/cargo/reference/environment-variables.html#dynamic-library-paths
fn main() {
    println!("cargo:rustc-link-lib=tensorflowlite_c");
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("lib").display());
    if cfg!(feature = "edgetpu") {
        println!("cargo:rustc-link-lib=edgetpu");
    }
}
