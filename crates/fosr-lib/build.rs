fn main() {
    println!("cargo:rerun-if-changed=default_topologies/");
    println!("cargo:rerun-if-changed=default_models");
}
