fn main() {
    for a in std::env::args().skip(1) {
        let b = std::fs::read(&a).unwrap();
        println!("{}: {:?}", a, backend::proto::peek_root_digest(&b));
    }
}
