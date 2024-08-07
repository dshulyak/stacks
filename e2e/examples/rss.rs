use std::hint::black_box;

fn main() {
    let mut v = vec![0u8; 1 << 30];
    for i in v.iter_mut() {
        // this line should trigger page faults and will be captured as offset
        *i = 11;
    }
    black_box(v);
}
