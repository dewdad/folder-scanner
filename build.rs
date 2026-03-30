fn main() {
    // Make the TARGET triple available at compile time via env!("TARGET")
    // Used by self_update to match GitHub release assets
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
