use std::path::PathBuf;
use crate::journal::journal_reader::{JournalReader, JournalReaderError};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::zone::rr_set::RRSet;
use crate::rr_data::inter::rr_data::RRData;
use crate::utils::fqdn_utils::{decode_fqdn, encode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;

#[derive(Debug, Clone)]
pub struct Zone {
    ztype: ZoneTypes,
    class: RRClasses,
    sets: Trie<Vec<RRSet>>,
    journal_path: Option<PathBuf>
}

impl Default for Zone {

    fn default() -> Self {
        Self {
            ztype: Default::default(),
            class: Default::default(),
            sets: Trie::new(),
            journal_path: None
        }
    }
}

impl Zone {

    pub fn new(ztype: ZoneTypes, class: RRClasses) -> Self {
        Self {
            ztype,
            class,
            ..Default::default()
        }
    }

    pub fn new_with_jnl<P: Into<PathBuf>>(ztype: ZoneTypes, class: RRClasses, journal_path: P) -> Self {
        Self {
            ztype,
            class,
            journal_path: Some(journal_path.into()),
            ..Default::default()
        }
    }

    pub fn set_ztype(&mut self, ztype: ZoneTypes) {
        self.ztype = ztype;
    }

    pub fn ztype(&self) -> ZoneTypes {
        self.ztype
    }

    pub fn class(&self) -> RRClasses {
        self.class
    }

    pub fn is_authority(&self) -> bool {
        self.ztype.eq(&ZoneTypes::Master) || self.ztype.eq(&ZoneTypes::Slave)
    }

    pub fn add_record(&mut self, query: &str, rtype: RRTypes, ttl: u32, data: Box<dyn RRData>) {
        let key = encode_fqdn(query);

        match self.sets.get_mut(&key) {
            Some(sets) => {
                match sets
                        .iter_mut()
                        .find(|s| s.rtype().eq(&rtype)) {
                    Some(set) => set.add_data(ttl, data),
                    None => {
                        let mut set = RRSet::new(rtype, ttl);
                        set.add_data(ttl, data);
                        sets.push(set);
                    }
                }
            }
            None => {
                let mut set = RRSet::new(rtype, ttl);
                set.add_data(ttl, data);
                self.sets.insert(key, vec![set]);
            }
        }
    }

    pub fn remove_record(&mut self, query: &str, rtype: &RRTypes, data: &Box<dyn RRData>, min_records: usize) -> bool {
        let key = encode_fqdn(query);

        match self.sets.get_mut(&key) {
            Some(sets) => {
                match sets.iter().position(|s| s.rtype().eq(rtype)) {
                    Some(idx) => {
                        let set = sets.get_mut(idx).unwrap();

                        let removed = set.remove_data(&data, min_records);

                        if set.is_empty() {
                            sets.swap_remove(idx);
                        }

                        if sets.is_empty() {
                            self.sets.remove(&key);
                        }

                        removed
                    }
                    None => false
                }
            }
            None => false
        }
    }

    pub fn remove_rr_set(&mut self, query: &str, rtype: &RRTypes) -> Option<RRSet> {
        let key = encode_fqdn(query);

        match self.sets.get_mut(&key) {
            Some(sets) => {
                match sets.iter().position(|s| s.rtype().eq(rtype)) {
                    Some(idx) => {
                        let removed = sets.swap_remove(idx);

                        if sets.is_empty() {
                            self.sets.remove(&key);
                        }

                        Some(removed)
                    }
                    None => None
                }
            }
            None => None
        }
    }

    pub fn remove_all_records(&mut self, query: &str, protected_types: &[RRTypes]) {
        let key = encode_fqdn(query);

        if match self.sets.get_mut(&key) {
            Some(sets) => {
                sets.retain(|set| protected_types.contains(&set.rtype()));
                sets.is_empty()
            }
            None => false
        } {
            self.sets.remove(&key);
        }
    }
    /*
    pub fn add_record(&mut self, name: &str, record: Box<dyn RRData>) {
        let key = encode_fqdn(name);
        match self.rr_data.get_mut(&key) {
            Some(rr_data) => {
                rr_data.entry(record.type()).or_insert(Vec::new()).push(record);
            }
            None => {
                let mut rrmap = BTreeMap::new();
                rrmap.insert(record.rtype(), vec![record]);
                self.rr_data.insert(key, rrmap);
            }
        }

        //self.rr_data
        //    .entry(name.to_string()).or_insert_with(IndexMap::new)
        //    .entry(record.rtype()).or_insert(Vec::new()).push(record);

        //UPDATE SOA
        //ADD TO JOURNAL
    }
    */

    pub fn rr_set(&self, query: &str, rtype: &RRTypes) -> Option<&RRSet> {
        self.sets.get(&encode_fqdn(query))?.iter().find(|s| s.rtype().eq(rtype))
    }

    pub fn all_rr_sets(&self, query: &str) -> Option<&Vec<RRSet>> {
        self.sets.get(&encode_fqdn(query))
    }

    pub fn all_rr_sets_recursive(&self) -> impl Iterator<Item = (String, &Vec<RRSet>)> {
        self.sets.iter().map(|(key, records)| (decode_fqdn(key), records))
    }

    /*

    //METHOD 2
    pub fn delegation_point(&self, name: &str) -> Option<(String, &Vec<RRSet>)> {
        match self.rrmap.get_shallowest(&encode_fqdn(name)) {
            Some((name, sets)) => {
                if sets.iter().any(|set| set.rtype().eq(&RRTypes::Ns)) {
                    return Some((decode_fqdn(name), sets));
                }

                None
            }
            None => None
        }
    }

    */

    pub fn delegation_point(&self, query: &str) -> Option<(String, &RRSet)> {
        match self.sets.get_shallowest(&encode_fqdn(query)) {
            Some((name, sets)) => {
                sets
                    .iter()
                    .find(|s| s.rtype().eq(&RRTypes::Ns))
                    .map(|set| (decode_fqdn(name), set))
            }
            None => None
        }
    }

    pub fn journal_reader(&self) -> Result<JournalReader, JournalReaderError> {
        JournalReader::open(self.journal_path.as_ref().unwrap())
    }

    pub fn set_journal_path<P: Into<PathBuf>>(&mut self, journal_path: P) {
        self.journal_path = Some(journal_path.into());
    }

    pub fn journal_path(&self) -> Option<&PathBuf> {
        self.journal_path.as_ref()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
