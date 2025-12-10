use crate::utils::trie::node::{bit, Branch, Leaf, Node};

#[derive(Clone, Debug)]
pub struct Trie<V> {
    root: Option<Node<Vec<u8>, V>>
}

impl<V> Default for Trie<V> {

    fn default() -> Self {
        Self {
            root: None
        }
    }
}

impl<V> Trie<V> {

    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn nibble(key: &[u8], i: usize) -> usize {
        if i / 2 >= key.len() {
            return 0;
        }

        let b = key[i / 2];
        1 + if (i & 1) == 0 { (b >> 4) as usize } else { (b & 0x0F) as usize }
    }

    fn first_diff_nibble(a: &[u8], b: &[u8]) -> usize {
        let max_nibbles = 2 * a.len().max(b.len()) + 1;
        for i in 0..max_nibbles {
            if Self::nibble(a, i) != Self::nibble(b, i) {
                return i;
            }
        }
        0
    }

    pub fn insert(&mut self, key: Vec<u8>, val: V) -> Option<V> {
        Self::insert_at(&mut self.root, key, val)
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<V> {
        Self::remove_at(&mut self.root, key)
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let mut node = self.root.as_ref()?;
        let key = key;
        loop {
            match node {
                Node::Branch(br) => {
                    let n = Self::nibble(key, br.offset);
                    node = br.get_child(n)?;
                }
                Node::Leaf(leaf) => {
                    if leaf.key.as_slice() == key {
                        return Some(&leaf.val);
                    }
                    return None;
                }
            }
        }
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let mut node = self.root.as_mut()?;
        loop {
            match node {
                Node::Branch(br) => {
                    let n = Self::nibble(key, br.offset);
                    node = br.get_child_mut(n)?;
                }
                Node::Leaf(leaf) => {
                    if leaf.key.as_slice() == key {
                        return Some(&mut leaf.val);
                    }
                    return None;
                }
            }
        }
    }

    pub fn get_deepest(&self, query: &[u8]) -> Option<(&[u8], &V)> {
        let mut node = self.root.as_ref()?;
        let mut best: Option<(&[u8], &V)> = None;

        loop {
            match node {
                Node::Branch(br) => {
                    if br.has_child(0) {
                        if let Some(Node::Leaf(leaf)) = br.get_child(0) {
                            if is_prefix(leaf.key.as_slice(), query) {
                                best = Some((leaf.key.as_slice(), &leaf.val));
                            }
                        }
                    }

                    let n = Self::nibble(query, br.offset);
                    match br.get_child(n) {
                        Some(child) => node = child,
                        None => return best
                    }
                }
                Node::Leaf(leaf) => {
                    if is_prefix(leaf.key.as_slice(), query) {
                        return Some((leaf.key.as_slice(), &leaf.val));
                    }
                    return best;
                }
            }
        }
    }

    pub fn get_deepest_mut(&mut self, query: &[u8]) -> Option<(&[u8], &mut V)> {
        let best_key = {
            let mut node = self.root.as_mut()?;
            let mut best_key = None;

            loop {
                match node {
                    Node::Branch(br) => {
                        if br.has_child(0) {
                            if let Some(Node::Leaf(leaf)) = br.get_child(0) {
                                if is_prefix(leaf.key.as_slice(), query) {
                                    best_key = Some(leaf.key.to_vec());
                                }
                            }
                        }

                        let n = Self::nibble(query, br.offset);
                        match br.get_child_mut(n) {
                            Some(child) => node = child,
                            None => break
                        }
                    }
                    Node::Leaf(leaf) => {
                        if is_prefix(leaf.key.as_slice(), query) {
                            best_key = Some(leaf.key.to_vec());
                        }
                        break;
                    }
                }
            }

            best_key
        };

        let key = best_key?;

        let mut node = self.root.as_mut()?;
        loop {
            match node {
                Node::Branch(br) => {
                    let n = Self::nibble(key.as_slice(), br.offset);
                    node = br.get_child_mut(n)?;
                }
                Node::Leaf(leaf) => {
                    if leaf.key.as_slice() == key.as_slice() {
                        return Some((leaf.key.as_slice(), &mut leaf.val));
                    }
                    return None;
                }
            }
        }
    }

    pub fn get_shallowest(&self, query: &[u8]) -> Option<(&[u8], &V)> {
        let mut node = self.root.as_ref()?;

        loop {
            match node {
                Node::Branch(br) => {
                    if br.has_child(0) {
                        if let Some(Node::Leaf(leaf)) = br.get_child(0) {
                            if is_prefix(leaf.key.as_slice(), query) && !is_apex_key(&leaf.key) {
                                return Some((leaf.key.as_slice(), &leaf.val));
                            }
                        }
                    }

                    let n = Self::nibble(query, br.offset);
                    match br.get_child(n) {
                        Some(child) => node = child,
                        None => return None
                    }
                }
                Node::Leaf(leaf) => {
                    if is_prefix(leaf.key.as_slice(), query) && !is_apex_key(&leaf.key) {
                        return Some((leaf.key.as_slice(), &leaf.val));
                    }
                    return None;
                }
            }
        }
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    pub fn iter(&self) -> Entries<'_, V> {
        let mut stack = Vec::new();
        if let Some(root) = self.root.as_ref() {
            Entries::push_node(&mut stack, root);
        }
        Entries {
            stack
        }
    }

    /*
    fn insert_at(root: &mut Option<Node<Vec<u8>, V>>, key: Vec<u8>, val: V) -> Option<V> {
        match root {
            None => {
                *root = Some(Node::Leaf(Leaf::new(key, val)));
                None
            }
            Some(node) => {
                match node {
                    Node::Leaf(leaf) => {
                        if leaf.key.as_slice() == key.as_slice() {
                            return Some(std::mem::replace(&mut leaf.val, val));
                        }

                        let split = Self::first_diff_nibble(&leaf.key, &key);

                        let old_leaf = match std::mem::replace(node, Node::Branch(Branch::new(split))) {
                            Node::Leaf(l) => l,
                            _ => unreachable!(),
                        };

                        if let Node::Branch(br) = node {
                            let old_n = Self::nibble(&old_leaf.key, split);
                            br.insert_child(old_n, Node::Leaf(old_leaf));

                            let new_n = Self::nibble(&key, split);
                            br.insert_child(new_n, Node::Leaf(Leaf::new(key, val)));
                            None
                        } else {
                            unreachable!()
                        }
                    }
                    Node::Branch(br) => {
                        let n = Self::nibble(&key, br.offset);
                        if let Some(child) = br.get_child_mut(n) {
                            let mut tmp = Some(std::mem::replace(child, Node::Branch(Branch::default())));
                            let ret = Self::insert_at(&mut tmp, key, val);
                            *child = tmp.unwrap();
                            ret
                        } else {
                            br.insert_child(n, Node::Leaf(Leaf::new(key, val)));
                            None
                        }
                    }
                }
            }
        }
    }
    */

    fn insert_at(root: &mut Option<Node<Vec<u8>, V>>, key: Vec<u8>, val: V) -> Option<V> {
        match root {
            None => {
                *root = Some(Node::Leaf(Leaf::new(key, val)));
                None
            }
            Some(node) => match node {
                Node::Leaf(leaf) => {
                    if leaf.key.as_slice() == key.as_slice() {
                        return Some(std::mem::replace(&mut leaf.val, val));
                    }

                    let split = Self::first_diff_nibble(&leaf.key, &key);

                    let old_leaf = match std::mem::replace(node, Node::Branch(Branch::new(split))) {
                        Node::Leaf(l) => l,
                        _ => unreachable!(),
                    };

                    if let Node::Branch(br) = node {
                        let old_n = Self::nibble(&old_leaf.key, split);
                        br.insert_child(old_n, Node::Leaf(old_leaf));

                        let new_n = Self::nibble(&key, split);
                        br.insert_child(new_n, Node::Leaf(Leaf::new(key, val)));
                        None

                    } else {
                        unreachable!()
                    }
                }
                Node::Branch(br) => {
                    let rep_key = {
                        let mut child_ref: Option<&Node<Vec<u8>, V>> = None;
                        for i in 0..=16 {
                            if let Some(ch) = br.get_child(i) {
                                child_ref = Some(ch);
                                break;
                            }
                        }
                        let ch = child_ref.expect("branch must have at least one child");
                        Self::first_leaf_key(ch)
                    };

                    let new_split = Self::first_diff_nibble(&rep_key, &key);
                    let need_above = new_split < br.offset;

                    if need_above {
                        let old_node = std::mem::replace(node, Node::Branch(Branch::new(new_split)));

                        if let Node::Branch(new_parent) = node {
                            let old_n = Self::nibble(&rep_key, new_split);
                            new_parent.insert_child(old_n, old_node);

                            let new_n = Self::nibble(&key, new_split);
                            new_parent.insert_child(new_n, Node::Leaf(Leaf::new(key, val)));
                            return None;

                        } else {
                            unreachable!()
                        }
                    }

                    let n = Self::nibble(&key,  br.offset);
                    if let Some(child) = br.get_child_mut(n) {
                        let mut tmp = Some(std::mem::replace(child, Node::Branch(Branch::default())));
                        let ret = Self::insert_at(&mut tmp, key, val);
                        *child = tmp.unwrap();
                        return ret;

                    }

                    br.insert_child(n, Node::Leaf(Leaf::new(key, val)));
                    None
                }
            }
        }
    }

    fn first_leaf_key(mut cur: &Node<Vec<u8>, V>) -> Vec<u8> {
        loop {
            match cur {
                Node::Leaf(l) => return l.key.clone(),
                Node::Branch(b) => {
                    let mut next: Option<&Node<Vec<u8>, V>> = None;
                    for i in 0..=16 {
                        if let Some(ch) = b.get_child(i) {
                            next = Some(ch);
                            break;
                        }
                    }
                    cur = next.expect("branch must have at least one child");
                }
            }
        }
    }

    fn remove_at(root: &mut Option<Node<Vec<u8>, V>>, key: &[u8]) -> Option<V> {
        let mut cur = root.take();

        match cur.as_mut() {
            None => None,
            Some(Node::Leaf(leaf)) => {
                if leaf.key.as_slice() == key {
                    let Node::Leaf(Leaf { val, .. }) = cur.take().unwrap() else { unreachable!() };
                    return Some(val);
                }

                *root = cur;
                None
            }
            Some(Node::Branch(br)) => {
                let n = Self::nibble(key, br.offset);
                if !br.has_child(n) {
                    *root = cur;
                    return None;
                }

                let idx = br.idx_of(n).unwrap();
                let child_slot: &mut Node<Vec<u8>, V> = &mut br.twigs[idx];

                let mut tmp_child = Some(std::mem::replace(child_slot, Node::Branch(Branch {
                    offset: 0,
                    bitmap: 0,
                    twigs: Vec::new()
                })));

                let removed = Self::remove_at(&mut tmp_child, key);

                match tmp_child {
                    Some(next_child) => {
                        *child_slot = next_child;

                        if br.bitmap.count_ones() == 1 {
                            let only_child = br.twigs.remove(0);
                            cur = Some(only_child);
                        }

                        *root = cur;
                        removed
                    }

                    None => {
                        br.twigs.remove(idx);
                        br.bitmap &= !bit(n);

                        if br.bitmap == 0 {
                            *root = None;
                            removed

                        } else if br.bitmap.count_ones() == 1 {
                            let only_child = br.twigs.remove(0);
                            *root = Some(only_child);
                            removed

                        } else {
                            *root = cur;
                            removed
                        }
                    }
                }
            }
        }
    }
}

pub struct Entries<'a, V> {
    stack: Vec<Frame<'a, V>>
}

enum Frame<'a, V> {
    Branch { br: &'a Branch<Vec<u8>, V>, idx: usize },
    Leaf(&'a Leaf<Vec<u8>, V>)
}

impl<V> Entries<'_, V> {

    fn push_node<'a>(stack: &mut Vec<Frame<'a, V>>, node: &'a Node<Vec<u8>, V>) {
        match node {
            Node::Leaf(l) => stack.push(Frame::Leaf(l)),
            Node::Branch(b) => stack.push(Frame::Branch { br: b, idx: 0 })
        }
    }
}

impl<'a, V> Iterator for Entries<'a, V> {

    type Item = (&'a [u8], &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(frame) = self.stack.pop() {
            match frame {
                Frame::Leaf(leaf) => return Some((leaf.key.as_slice(), &leaf.val)),
                Frame::Branch { br, mut idx } => {
                    while idx <= 16 {
                        if let Some(child) = br.get_child(idx) {
                            self.stack.push(Frame::Branch { br, idx: idx + 1 });
                            match child {
                                Node::Leaf(l) => return Some((l.key.as_slice(), &l.val)),
                                Node::Branch(b) => {
                                    self.stack.push(Frame::Branch { br: b, idx: 0 });
                                    break;
                                }
                            }
                        }
                        idx += 1;
                    }
                }
            }
        }
        None
    }
}



fn is_apex_key(k: &[u8]) -> bool {
    k.is_empty() || (k.len() == 1 && k[0] == 0)
}

fn is_prefix(a: &[u8], b: &[u8]) -> bool {
    b.len() >= a.len() && &b[..a.len()] == a
}
