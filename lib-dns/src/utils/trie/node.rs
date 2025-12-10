#[derive(Clone, Debug)]
pub enum Node<K, V> {
    Branch(Branch<K, V>),
    Leaf(Leaf<K, V>)
}

#[derive(Clone, Debug)]
pub struct Branch<K, V> {
    pub(crate) offset: usize,
    pub(crate) bitmap: u32,
    pub(crate) twigs: Vec<Node<K, V>>
}

impl<K, V> Default for Branch<K, V> {

    fn default() -> Self {
        Self {
            offset: 0,
            bitmap: 0,
            twigs: Vec::new()
        }
    }
}

impl<K, V> Branch<K, V> {

    pub fn new(offset: usize) -> Self {
        Self {
            offset,
            ..Self::default()
        }
    }

    pub fn has_child(&self, n: usize) -> bool {
        (self.bitmap & bit(n)) != 0
    }

    pub fn rank(bitmap: u32, n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        let mask = (1u32 << n) - 1;
        (bitmap & mask).count_ones() as usize
    }

    pub fn idx_of(&self, n: usize) -> Option<usize> {
        if self.has_child(n) {
            return Some(Self::rank(self.bitmap, n));
        }

        None
    }

    pub fn insert_child(&mut self, n: usize, node: Node<K, V>) {
        let idx = Self::rank(self.bitmap, n);
        self.twigs.insert(idx, node);
        self.bitmap |= bit(n);
    }

    pub fn get_child_mut(&mut self, n: usize) -> Option<&mut Node<K, V>> {
        self.idx_of(n).map(|i| &mut self.twigs[i])
    }

    pub fn get_child(&self, n: usize) -> Option<&Node<K, V>> {
        self.idx_of(n).map(|i| &self.twigs[i])
    }
}

#[derive(Clone, Debug, Default)]
pub struct Leaf<K, V> {
    pub(crate) key: K,
    pub(crate) val: V
}

impl<K, V> Leaf<K, V> {

    pub fn new(key: K, val: V) -> Self {
        Self {
            key,
            val
        }
    }
}

pub fn bit(n: usize) -> u32 {
    debug_assert!(n < 32);
    1u32 << n
}
