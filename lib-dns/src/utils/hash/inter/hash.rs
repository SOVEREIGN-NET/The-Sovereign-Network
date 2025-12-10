pub trait Hash {

    type Output: AsRef<[u8]>;
    const BLOCK_SIZE: usize;

    fn new() -> Self;

    fn get_value(&mut self) -> Self::Output;

    fn reset(&mut self);

    fn update(&mut self, buf: &[u8], off: usize, length: usize);
}
