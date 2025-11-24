#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub struct ByteWrapper<const T: usize> {
    b: [u8; T]
}

impl<const T: usize> ByteWrapper<T> {

    pub fn new(b: [u8; T]) -> Self {
        Self {
            b
        }
    }
}
