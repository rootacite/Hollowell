
fn main() {
    println!("cargo:rustc-link-arg={}", "../obj/hexer.o");
}