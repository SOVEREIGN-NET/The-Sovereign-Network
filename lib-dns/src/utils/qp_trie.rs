use std::mem;

#[derive(Debug, Clone)]
pub struct QpTrie<V> {
    root: Node<V>
}

#[derive(Debug, Clone)]
struct Node<V> {
    prefix: Vec<u8>,
    prefix_len: usize,
    value: Option<V>,
    bitmap: u16,
    children: Vec<Box<Node<V>>>
}

impl<V> Default for QpTrie<V> {

    fn default() -> Self {
        Self {
            root: Node {
                prefix: Vec::new(),
                prefix_len: 0,
                value: None,
                bitmap: 0,
                children: Vec::new()
            }
        }
    }
}

impl<V> Node<V> {

    fn child_index(&self, nib: u8) -> Option<usize> {
        if Self::bit_is_set(self.bitmap, nib) {
            return Some(Self::rank(self.bitmap, nib));
        }

        None
    }

    fn attach_child(&mut self, nib: u8, child: Box<Node<V>>) {
        let idx = Self::rank(self.bitmap, nib);
        self.bitmap |= 1u16 << nib;
        self.children.insert(idx, child);
    }

    fn bit_is_set(bm: u16, nib: u8) -> bool {
        (bm >> nib) & 1 == 1
    }

    fn rank(bm: u16, nib: u8) -> usize {
        let mask = if nib == 0 {
            0
        } else {
            (1u16 << nib) - 1
        };
        (bm & mask).count_ones() as usize
    }
}

impl<V> QpTrie<V> {

    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: Vec<u8>, val: V) -> Option<V> {
        let key_len = nibbles_len(&key);
        Self::insert_at(&mut self.root, &key, 0, key_len, val)
    }

    fn insert_at<X>(node: &mut Node<X>, key: &[u8], mut off: usize, key_len: usize, mut val: X) -> Option<X> {
        let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
        if lcp < node.prefix_len {
            let branch_nib_old = get_nibble(&node.prefix, lcp);
            let (old_suffix_bytes, old_suffix_len) = slice_nibbles(&node.prefix, lcp + 1, node.prefix_len);

            let old_value = node.value.take();
            let old_bitmap = node.bitmap;
            let old_children = mem::take(&mut node.children);
            let old_child = Box::new(Node {
                prefix: old_suffix_bytes,
                prefix_len: old_suffix_len,
                value: old_value,
                bitmap: old_bitmap,
                children: old_children,
            });

            let (new_pref_bytes, _new_len) = slice_nibbles(&node.prefix, 0, lcp);
            node.prefix = new_pref_bytes;
            node.prefix_len = lcp;
            node.bitmap = 0;
            node.children = Vec::new();

            node.attach_child(branch_nib_old, old_child);
        }

        off += common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);

        if off == key_len {
            return mem::replace(&mut node.value, Some(val));
        }

        let nib = get_nibble(key, off);
        if let Some(idx) = node.child_index(nib) {
            return Self::insert_at(&mut node.children[idx], key, off + 1, key_len, val);
        }

        let (leaf_pref_bytes, leaf_pref_len) = slice_nibbles(key, off + 1, key_len);
        let leaf = Box::new(Node {
            prefix: leaf_pref_bytes,
            prefix_len: leaf_pref_len,
            value: Some(val),
            bitmap: 0,
            children: Vec::new(),
        });
        node.attach_child(nib, leaf);
        None
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let key_len = nibbles_len(key);
        Self::get_exact_at(&self.root, key, 0, key_len)
    }

    fn get_exact_at<'a, X>(node: &'a Node<X>, key: &[u8], mut off: usize, key_len: usize) -> Option<&'a X> {
        let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
        if lcp < node.prefix_len {
            return None;
        }
        off += lcp;

        if off == key_len {
            return node.value.as_ref();
        }

        let nib = get_nibble(key, off);
        if let Some(idx) = node.child_index(nib) {
            return Self::get_exact_at(&node.children[idx], key, off + 1, key_len);
        }

        None
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let key_len = nibbles_len(key);
        Self::get_exact_at_mut(&mut self.root, key, 0, key_len)
    }

    fn get_exact_at_mut<'a, X>(node: &'a mut Node<X>, key: &[u8], mut off: usize, key_len: usize) -> Option<&'a mut X> {
        let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
        if lcp < node.prefix_len {
            return None;
        }
        off += lcp;

        if off == key_len {
            return node.value.as_mut();
        }
        let nib = get_nibble(key, off);
        if let Some(idx) = node.child_index(nib) {
            return Self::get_exact_at_mut(&mut node.children[idx], key, off + 1, key_len);
        }

        None
    }

    pub fn get_longest_prefix(&self, key: &[u8]) -> Option<&V> {
        let key_len = nibbles_len(key);
        Self::get_longest_at(&self.root, key, 0, key_len, None).map(|(v, _)| v)
    }

    pub fn get_longest_prefix_with_key(&self, key: &[u8]) -> Option<(Vec<u8>, &V)> {
        let key_len = nibbles_len(&key);
        let best = Self::get_longest_at(&self.root, &key, 0, key_len, None)?;
        let (_, matched_nibbles) = best;

        let (matched_raw, _len) = slice_nibbles(&key, 0, matched_nibbles);
        Some((matched_raw, best.0))
    }

    fn get_longest_at<'a, X>(node: &'a Node<X>, key: &[u8], mut off: usize, key_len: usize, best: Option<(&'a X, usize)>) -> Option<(&'a X, usize)> {
        let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
        if lcp < node.prefix_len {
            return best;
        }
        off += lcp;

        let mut best = best;
        if let Some(v) = node.value.as_ref() {
            best = Some((v, off));
        }

        if off == key_len {
            return best;
        }

        let nib = get_nibble(key, off);
        if let Some(idx) = node.child_index(nib) {
            return Self::get_longest_at(&node.children[idx], key, off + 1, key_len, best);
        }

        best
    }
}

fn nibbles_len(bytes: &[u8]) -> usize {
    bytes.len() * 2
}

fn get_nibble(bytes: &[u8], i: usize) -> u8 {
    let b = bytes[i >> 1];

    if (i & 1) == 0 {
        b >> 4

    } else {
        b & 0x0F
    }
}

fn slice_nibbles(src: &[u8], start: usize, end: usize) -> (Vec<u8>, usize) {
    debug_assert!(end >= start);
    let mut out = Vec::with_capacity(((end - start) + 1) / 2);
    let mut out_len = 0;

    for i in start..end {
        let nib = get_nibble(src, i);

        if (out_len & 1) == 0 {
            out.push(nib << 4);

        } else {
            let last = out.last_mut().unwrap();
            *last |= nib;
        }

        out_len += 1;
    }
    (out, out_len)
}

fn common_prefix_len(node_pref: &[u8], node_pref_len: usize, key: &[u8], key_off: usize, key_len: usize) -> usize {
    let max = node_pref_len.min(key_len - key_off);
    let mut i = 0;
    while i < max {
        if get_nibble(node_pref, i) != get_nibble(key, key_off + i) {
            break;
        }
        i += 1;
    }
    i
}
