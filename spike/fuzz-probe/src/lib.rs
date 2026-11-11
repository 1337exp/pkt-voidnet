#![no_std]
/// Toy parser with a planted bug: a length byte of 0xFF reads past the end.
pub fn parse(data: &[u8]) -> usize {
    if data.len() < 2 || data[0] != 0x42 {
        return 0;
    }
    let n = data[1] as usize;
    let mut sum = 0usize;
    for i in 0..n {
        sum += data[2 + i] as usize; // panics (index out of bounds) when n > len-2
    }
    sum
}
