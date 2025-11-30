use time::OffsetDateTime;

fn main() {
    // Get the current year
    let now = OffsetDateTime::now_utc();
    let year = now.year();

    // Pass this variable to your main Rust code as an environment variable
    println!("cargo:rustc-env=BUILD_YEAR={}", year);
}
