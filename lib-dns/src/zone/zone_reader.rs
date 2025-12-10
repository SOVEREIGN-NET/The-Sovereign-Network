use std::fmt;
use std::fmt::Formatter;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::str::FromStr;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::fqdn_utils::fqdn_to_relative;
use crate::zone::inter::zone_rr_data::ZoneRRData;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParserState {
    Init,
    Common,
    Directive,
    Data,
    QString
}

pub struct ZoneReader {
    reader: BufReader<File>,
    origin: String,
    class: RRClasses,
    default_ttl: u32
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZoneReaderError {
    _type: ErrorKind,
    message: String
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    PathNotFound,
    TypeNotFound,
    Parsing,
    WrongClass,
    Format,
    ExtraRRData,
    UnexpectedEof
}

impl ZoneReaderError {

    pub fn new(_type: ErrorKind, message: &str) -> Self {
        Self {
            _type,
            message: message.to_string()
        }
    }
}

impl fmt::Display for ZoneReaderError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self._type, self.message)
    }
}

impl ZoneReader {

    pub fn open<P: Into<PathBuf>>(file_path: P, origin: &str, class: RRClasses) -> Result<Self, ZoneReaderError> {
        let file = File::open(file_path.into()).map_err(|e| ZoneReaderError::new(ErrorKind::PathNotFound, &e.to_string()))?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            origin: origin.to_lowercase(),
            class,
            default_ttl: 300
        })
    }

    pub fn read_record(&mut self) -> Result<Option<(String, RRTypes, u32, Box<dyn ZoneRRData>)>, ZoneReaderError> {
        let mut state = ParserState::Init;
        let mut paren_count: u8 = 0;

        let mut name = String::new();
        let mut _type;
        let mut ttl = self.default_ttl;

        let mut directive_buf = String::new();

        let mut record: Option<(String, RRTypes, u32, Box<dyn ZoneRRData>)> = None;
        let mut data_count = 0;

        let mut line = String::new();
        loop {
            line.clear();

            match self.reader.read_line(&mut line) {
                Ok(length) => {
                    if line.ends_with('\n') {
                        line.pop();
                        if line.ends_with('\r') {
                            line.pop();
                        }
                    }

                    if length == 0 {
                        break;
                    }

                    let mut pos = 0;
                    let mut quoted_buf = String::new();

                    for part in line.as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
                        let part_len = part.len();
                        let mut word_len = part_len;

                        if part[0] == b';' && state != ParserState::QString {
                            break;
                        }

                        match part[part_len - 1] {
                            b' ' | b'\t' | b'\n' => {
                                word_len -= 1;
                            }
                            b'(' => {
                                paren_count += 1;
                                word_len -= 1;
                            }
                            b')' => {
                                paren_count -= 1;
                                word_len -= 1;
                            }
                            _ => {}
                        }

                        if word_len == 0 && (part[0] == b'\n' || state != ParserState::Init) {
                            continue;
                        }

                        match state {
                            ParserState::Init => {
                                let word = String::from_utf8(part[0..word_len].to_vec())
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?.to_lowercase();

                                if pos == 0 && paren_count == 0 {
                                    if word.starts_with('$') {
                                        directive_buf = word;
                                        state = ParserState::Directive;

                                    } else {
                                        if word_len > 0 {
                                            name = word;
                                        }

                                        state = ParserState::Common;
                                    }
                                }
                            }
                            ParserState::Common => {
                                let word = String::from_utf8(part[0..word_len].to_vec())
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?.to_uppercase();

                                if let Ok(c) = RRClasses::from_str(&word) {
                                    if !c.eq(&self.class) {
                                        return Err(ZoneReaderError::new(ErrorKind::WrongClass, "invalid class found"));
                                    }

                                } else if let Ok(t) = RRTypes::from_str(&word) {
                                    _type = t;
                                    state = ParserState::Data;
                                    data_count = 0;
                                    record = Some((self.absolute_name(&name), _type, ttl, <dyn ZoneRRData>::new(_type, &self.class)
                                        .ok_or_else(|| ZoneReaderError::new(ErrorKind::TypeNotFound, &format!("record type {} not found", _type)))?));

                                } else {
                                    ttl = word.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, &format!("unable to parse ttl {}", word)))?;
                                }
                            }
                            ParserState::Directive => {
                                let value = String::from_utf8(part[0..word_len].to_vec())
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?.to_lowercase();

                                match directive_buf.as_str() {
                                    "$ttl" => self.default_ttl = value.parse()
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, &format!("unable to parse default_ttl {}", value)))?,
                                    "$origin" => self.origin = value.strip_suffix('.')
                                        .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, &format!("origin is not fully qualified (missing trailing dot) {}", value)))?.to_string(),
                                    _ => return Err(ZoneReaderError::new(ErrorKind::Format, &format!("unknown directive {}", directive_buf)))
                                }

                                state = ParserState::Init;
                            }
                            ParserState::Data => {
                                if part[0] == b'"' {
                                    if part[word_len - 1] == b'"' {
                                        record.as_mut().unwrap().3.set_data(data_count, &String::from_utf8(part[1..word_len - 1].to_vec())
                                            .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?)?;

                                        data_count += 1;

                                    } else {
                                        state = ParserState::QString;
                                        quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec())
                                            .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?, part[word_len] as char);
                                    }

                                } else {
                                    record.as_mut().unwrap().3.set_data(data_count, &String::from_utf8(part[0..word_len].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?)?;

                                    data_count += 1;
                                }
                            }
                            ParserState::QString => {
                                if part[word_len - 1] == b'"' {
                                    quoted_buf.push_str(&format!("{}", String::from_utf8(part[0..word_len - 1].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?));

                                    record.as_mut().unwrap().3.set_data(data_count, &quoted_buf)?;

                                    data_count += 1;
                                    state = ParserState::Data;

                                } else {
                                    quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::Parsing, "unable to parse string"))?, part[word_len] as char));
                                }
                            }
                        }

                        pos += part_len;
                    }

                    if record.is_some() && paren_count == 0 {
                        return Ok(record);
                    }
                }
                Err(e) => return Err(ZoneReaderError::new(ErrorKind::UnexpectedEof, &e.to_string()))
            }
        }

        Ok(record)
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn absolute_name(&self, name: &str) -> String {
        if name.eq("@") {
            return String::new();
        }

        if name.ends_with('.') {
            return fqdn_to_relative(&self.origin, name.strip_suffix('.').unwrap()).unwrap();
        }

        name.to_string()
    }

    pub fn records(&mut self) -> ZoneReaderIter {
        ZoneReaderIter {
            reader: self
        }
    }
}

pub struct ZoneReaderIter<'a> {
    reader: &'a mut ZoneReader
}

impl<'a> Iterator for ZoneReaderIter<'a> {

    type Item = Result<(String, RRTypes, u32, Box<dyn ZoneRRData>), ZoneReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_record() {
            Ok(Some(rec)) => Some(Ok(rec)),
            Ok(None) => None,
            Err(e) => Some(Err(e))
        }
    }
}
