use std::io;
use crate::journal::journal::Journal;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::index_map::IndexMap;
use crate::zone::inter::zone_types::ZoneTypes;
use crate::zone::zone_reader::ZoneReader;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    records: IndexMap<String, IndexMap<RRTypes, Vec<Box<dyn RecordBase>>>>,
    journal: Option<Journal>
}

impl Default for Zone {

    fn default() -> Self {
        Self {
            _type: Default::default(),
            records: IndexMap::new(),
            journal: None
        }
    }
}

impl Zone {

    pub fn new(_type: ZoneTypes) -> Self {
        Self {
            _type,
            ..Default::default()
        }
    }

    /*
    ///Open a file at the root zone otherwise it will be a sub of this
    pub fn open(&mut self, file_path: &str, domain: &str) -> io::Result<()> {
        let mut zone = Self::new(ZoneTypes::Master);

        let mut reader = ZoneReader::open(file_path, domain)?;
        for (name, record) in reader.iter() {
            match name.as_str() {
                "." => self.add_record(record), //BE CAREFUL WITH THIS ONE - DONT ALLOW MOST OF THE TIME
                "@" => zone.add_record(record),
                _ => zone.add_record_to(&name, record, ZoneTypes::Master)
            }
        }

        self.add_zone_to(&reader.get_origin(), zone, ZoneTypes::Hint);

        Ok(())
    }
    */

    pub fn set_type(&mut self, _type: ZoneTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> ZoneTypes {
        self._type
    }

    pub fn is_authority(&self) -> bool {
        self._type.eq(&ZoneTypes::Master) || self._type.eq(&ZoneTypes::Slave)
    }

    pub fn add_record(&mut self, name: &str, record: Box<dyn RecordBase>) {
        self.records
            .entry(name.to_string()).or_insert_with(IndexMap::new)
            .entry(record.get_type()).or_insert(Vec::new()).push(record);

        //UPDATE SOA
        //ADD TO JOURNAL
    }

    pub fn get_records(&self, name: &str, _type: &RRTypes) -> Option<&Vec<Box<dyn RecordBase>>> {
        self.records.get(name)?.get(_type)
    }

    pub fn get_all_records(&self, name: &str) -> Option<&IndexMap<RRTypes, Vec<Box<dyn RecordBase>>>> {
        self.records.get(name)
    }

    /*
    pub fn get_all_records_recursive(&self) -> IndexMap<String, Vec<&Box<dyn RecordBase>>> {
        let mut res = IndexMap::new();
        self.collect_records(String::new(), &mut res);
        res
    }

    fn collect_records<'a>(&'a self, fqdn: String, map: &mut IndexMap<String, Vec<&'a Box<dyn RecordBase>>>) {
        let recs: Vec<&Box<dyn RecordBase>> = self
            .records
            .iter()
            .filter(|(ty, _)| **ty != RRTypes::Soa)
            .flat_map(|(_, v)| v.iter())
            .collect();

        if !recs.is_empty() {
            map.insert(fqdn.to_string(), recs);
        }

        for (label, child) in &self.children {
            let is_delegated = child.records.get(&RRTypes::Soa).map_or(false, |recs| !recs.is_empty());

            if is_delegated {
                continue;
            }

            child.collect_records(format!("{}.{}", label, fqdn), map);
        }
    }
    */

    /*
    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = Some(journal);
    }

    pub fn set_journal_for(&mut self, name: &str, journal: Journal) -> io::Result<()> {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        let mut current = self;

        for label in labels {
            current = current.children.get_mut(label).ok_or(io::ErrorKind::NotFound)?;
        }

        current.journal = Some(journal);

        Ok(())
    }

    pub fn get_journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    pub fn get_journal_mut(&mut self) -> Option<&mut Journal> {
        self.journal.as_mut()
    }*/

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
