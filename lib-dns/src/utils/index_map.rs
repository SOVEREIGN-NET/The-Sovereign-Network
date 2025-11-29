use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Bound, RangeBounds};

#[derive(Debug, Clone, PartialEq)]
pub struct IndexMap<K: Eq + Hash, V> {
    map: HashMap<K, V>,
    keys: Vec<K>,
}

impl<K, V> IndexMap<K, V>
where
    K: Eq + Hash + Clone
{

    pub fn new() -> Self {
        IndexMap {
            map: HashMap::new(),
            keys: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.map.contains_key(&key) {
            self.map.insert(key.clone(), value)
        } else {
            self.keys.push(key.clone());
            self.map.insert(key, value)
        }
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.map.contains_key(key)
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.map.get(key)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.map.get_mut(key)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let out = self.map.remove(key);
        if out.is_some() {
            self.keys.retain(|k| k.borrow() != key);
        }
        out
    }

    pub fn entry(&mut self, key: K) -> Entry<K, V> {
        match self.map.entry(key.clone()) {
            Entry::Occupied(occupied) => {
                Entry::Occupied(occupied)
            }
            Entry::Vacant(vacant) => {
                self.keys.push(key.clone());
                Entry::Vacant(vacant)
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys.iter().filter_map(move |key| {
            let value = self.map.get(key)?;
            Some((key, value))
        })
    }

    pub fn iter_mut(&mut self) -> IndexMapIterMut<'_, K, V> {
        IndexMapIterMut {
            map: &mut self.map,
            keys: &self.keys,
            idx: 0,
            _phantom: PhantomData,
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.keys.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values()
    }

    pub fn range<R>(&self, bounds: R) -> impl Iterator<Item = (&K, &V)>
    where
        R: RangeBounds<K>
    {
        let key_to_index: HashMap<_, _> = self.keys.iter().enumerate().map(|(i, k)| (k.clone(), i)).collect();

        let start_idx = match bounds.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(k) => *key_to_index.get(k).unwrap_or(&self.keys.len()),
            Bound::Excluded(k) => key_to_index.get(k).map(|i| i + 1).unwrap_or(self.keys.len())
        };

        let end_idx = match bounds.end_bound() {
            Bound::Unbounded => self.keys.len(),
            Bound::Included(k) => key_to_index.get(k).map(|i| i + 1).unwrap_or(self.keys.len()),
            Bound::Excluded(k) => *key_to_index.get(k).unwrap_or(&self.keys.len())
        };

        self.keys[start_idx..end_idx]
            .iter()
            .filter_map(move |k| self.map.get(k).map(|v| (k, v)))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn drain(&mut self) -> impl Iterator<Item = (K, V)> + use<'_, K, V> {
        self.keys
            .drain(..)
            .filter_map(|key| self.map.remove(&key).map(|v| (key, v)))
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

pub struct IndexMapIter<'a, K: Eq + Hash, V> {
    inner: &'a IndexMap<K, V>,
    idx: usize
}

impl<'a, K: Eq + Hash, V> Iterator for IndexMapIter<'a, K, V> {

    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.inner.keys.len() {
            let k = &self.inner.keys[self.idx];
            self.idx += 1;
            if let Some(v) = self.inner.map.get(k) {
                return Some((k, v));
            }
        }
        None
    }
}

impl<'a, K: Eq + Hash + Clone, V> IntoIterator for &'a IndexMap<K, V> {

    type Item = (&'a K, &'a V);
    type IntoIter = IndexMapIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        IndexMapIter { inner: self, idx: 0 }
    }
}

pub struct IndexMapIterMut<'a, K: Eq + Hash, V> {
    map: &'a mut HashMap<K, V>,
    keys: &'a [K],
    idx: usize,
    _phantom: PhantomData<&'a mut V>,
}

impl<'a, K: Eq + Hash, V> Iterator for IndexMapIterMut<'a, K, V> {

    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.keys.len() {
            let k_ref: &K = &self.keys[self.idx];
            self.idx += 1;
            if let Some(v) = self.map.get_mut(k_ref) {
                let v_ptr: *mut V = v;
                return Some((k_ref, unsafe { &mut *v_ptr }));
            }
        }
        None
    }
}

impl<'a, K: Eq + Hash + Clone, V> IntoIterator for &'a mut IndexMap<K, V> {

    type Item = (&'a K, &'a mut V);
    type IntoIter = IndexMapIterMut<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

pub struct IndexMapIntoIter<K: Eq + Hash, V> {
    keys_iter: std::vec::IntoIter<K>,
    map: HashMap<K, V>,
}

impl<K: Eq + Hash, V> Iterator for IndexMapIntoIter<K, V> {

    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(k) = self.keys_iter.next() {
            if let Some(v) = self.map.remove(&k) {
                return Some((k, v));
            }
        }
        None
    }
}

impl<K: Eq + Hash + Clone, V> IntoIterator for IndexMap<K, V> {

    type Item = (K, V);
    type IntoIter = IndexMapIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        IndexMapIntoIter {
            keys_iter: self.keys.into_iter(),
            map: self.map,
        }
    }
}
