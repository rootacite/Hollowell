
fn main() {
    println!("cargo:rerun-if-changed=../obj/hexer.o");
    println!("cargo:rustc-link-arg={}", "../obj/hexer.o");
}