use std::fmt;
use std::fmt::Formatter;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use crate::journal::inter::txn_op_codes::TxnOpCodes;
use crate::journal::txn::Txn;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;
use crate::utils::fqdn_utils::unpack_fqdn;

#[derive(Default)]
pub struct JournalHeader {
    begin_serial: u32,
    begin_offset: u32,
    end_serial: u32,
    end_offset: u32,
    index_size: u32,
    source_serial: u32,
    flags: u8
}

impl JournalHeader {

    pub fn begin_serial(&self) -> u32 {
        self.begin_serial
    }

    pub fn begin_offset(&self) -> u32 {
        self.begin_offset
    }

    pub fn end_serial(&self) -> u32 {
        self.end_serial
    }

    pub fn end_offset(&self) -> u32 {
        self.end_offset
    }

    pub fn index_size(&self) -> u32 {
        self.index_size
    }

    pub fn source_serial(&self) -> u32 {
        self.source_serial
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }
}

pub struct JournalReader {
    reader: BufReader<File>,
    headers: Option<JournalHeader>
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JournalReaderError {
    _type: ErrorKind,
    message: String
}

impl fmt::Display for JournalReaderError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self._type, self.message)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    PathNotFound,
    ParseErr,
    ReadErr,
    ClassNotFound,
    TypeNotFound,
    UnexpectedEof
}

impl JournalReaderError {

    pub fn new(_type: ErrorKind, message: &str) -> Self {
        Self {
            _type,
            message: message.to_string()
        }
    }
}

impl JournalReader {

    pub fn open<P: Into<PathBuf>>(file_path: P) -> Result<Self, JournalReaderError> {
        let file = File::open(file_path.into()).map_err(|e| JournalReaderError::new(ErrorKind::PathNotFound, &e.to_string()))?;

        Ok(Self {
            reader: BufReader::new(file),
            headers: None
        })
    }

    pub fn headers(&mut self) -> Result<&JournalHeader, JournalReaderError> {
        if self.headers.is_none() {
            return self.read_headers();
        }

        self.headers.as_ref().ok_or(JournalReaderError::new(ErrorKind::ReadErr, "header not found"))
    }

    fn read_headers(&mut self) -> Result<&JournalHeader, JournalReaderError> {
        let mut buf = vec![0u8; 64];
        self.reader.read_exact(&mut buf)
            .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;

        // Magic (first 16 bytes): ";BIND LOG V9\n" or ";BIND LOG V9.2\n"
        let magic = true;//&buf[0..16];
        let v9 = b";BIND LOG V9\n";
        let v92 = b";BIND LOG V9.2\n";
        //if !(magic.starts_with(v9) || magic.starts_with(v92)) {
        //    //return Err(io::Error::new(io::ErrorKind::InvalidData, "bad .jnl magic"));
        //}

        //let is_v92 = magic.starts_with(v92);

        let begin_serial = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let begin_offset = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let end_serial = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let end_offset = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let index_size = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let source_serial = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let flags = buf[40];

        // ===== 2) OPTIONAL INDEX =====
        // Each index entry is 8 bytes: [serial(4) | offset(4)]
        //reader.seek(SeekFrom::Current((index_size as i64) * 8))
        //    .map_err(|e| JournalReaderError::new(ErrorKind::ReadErr, "unable to seek to position"))?;

        // ===== 3) POSITION TO FIRST TRANSACTION =====
        self.reader.seek(SeekFrom::Start(begin_offset as u64))
            .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, "unable to seek to position"))?;

        self.headers = Some(JournalHeader {
            begin_serial,
            begin_offset,
            end_serial,
            end_offset,
            index_size,
            source_serial,
            flags
        });

        self.headers.as_ref().ok_or(JournalReaderError::new(ErrorKind::ReadErr, "header not found"))
    }

    pub fn read_txn(&mut self) -> Result<Option<Txn>, JournalReaderError> {
        if self.headers.is_none() {
            self.read_headers()?;
        }

        let magic = true;

        if self.reader.stream_position()
                .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, "unable to find position"))? >= self.headers.as_ref().unwrap().end_offset as u64 {
            return Ok(None);
        }

        let (size, _rr_count, serial_0, serial_1) = match magic {
            true => {
                let mut buf = vec![0u8; 16];
                self.reader.read_exact(&mut buf)
                    .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;
                let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let rr_count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let serial_0 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let serial_1 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                (size, Some(rr_count), serial_0, serial_1)
            }
            false => {
                let mut buf = vec![0u8; 12];
                self.reader.read_exact(&mut buf)
                    .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;
                let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let serial_0 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let serial_1 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                (size, None, serial_0, serial_1)
            }
        };

        let mut remaining = size;
        let mut txn = Txn::new(serial_0, serial_1);
        let mut phase = TxnOpCodes::Delete;
        let mut seen_soa = 0;

        while remaining > 0 {
            let mut buf = vec![0u8; 4];
            self.reader.read_exact(&mut buf)
                .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;
            let rr_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            remaining -= 4 + rr_len;

            buf = vec![0u8; rr_len as usize];
            self.reader.read_exact(&mut buf)
                .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;

            let mut off = 0;

            let (name, length) = unpack_fqdn(&buf, off);
            off += length;

            let _type = RRTypes::try_from(u16::from_be_bytes([buf[off], buf[off+1]]))
                .map_err(|e| JournalReaderError::new(ErrorKind::TypeNotFound, &e.to_string()))?;

            if _type == RRTypes::Soa {
                seen_soa += 1;

                if seen_soa == 2 {
                    phase = TxnOpCodes::Add;
                }

                continue;
            }

            let class = RRClasses::try_from(u16::from_be_bytes([buf[off+2], buf[off+3]]))
                .map_err(|e| JournalReaderError::new(ErrorKind::ClassNotFound, &e.to_string()))?;
            let ttl = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);

            let length = u16::from_be_bytes([buf[off+8], buf[off+9]]) as usize;
            let data = match length {
                0 => None,
                _ => Some(<dyn RRData>::from_bytes_ambiguous(&buf[off+10..off+10+length], &_type, &class)
                    .map_err(|_| JournalReaderError::new(ErrorKind::TypeNotFound, &format!("record type {} not found", _type)))?)
            };
            txn.add_record(phase, &name, class, _type, ttl, data);
        }

        Ok(Some(txn))
    }

    pub fn seek(&mut self, serial: u32) -> Result<(), JournalReaderError> {
        match self.headers.as_ref() {
            Some(headers) => {
                self.reader.seek(SeekFrom::Start(headers.begin_offset as u64))
                    .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, "unable to seek to position"))?;
            }
            None => {
                self.read_headers()?;
            }
        }

        if serial == self.headers.as_ref().unwrap().begin_serial {
            return Ok(());
        }

        if serial < self.headers.as_ref().unwrap().begin_serial ||
                serial >= self.headers.as_ref().unwrap().end_serial {
            return Err(JournalReaderError::new(ErrorKind::ReadErr, "serial out of bounds"));
        }

        let magic = true;

        loop {
            let (size, _rr_count, serial_0, serial_1) = match magic {
                true => {
                    let mut buf = vec![0u8; 16];
                    self.reader.read_exact(&mut buf)
                        .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;
                    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let rr_count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let serial_0 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                    let serial_1 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                    (size, Some(rr_count), serial_0, serial_1)
                }
                false => {
                    let mut buf = vec![0u8; 12];
                    self.reader.read_exact(&mut buf)
                        .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, &format!("unable to read next {} bytes", buf.len())))?;
                    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let serial_0 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let serial_1 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                    (size, None, serial_0, serial_1)
                }
            };

            if serial_0 <= serial {
                self.reader.seek(SeekFrom::Current(size as i64))
                    .map_err(|_| JournalReaderError::new(ErrorKind::ReadErr, "unable to seek to position"))?;
            }

            if serial_1 >= serial {
                break;
            }
        }

        Ok(())
    }

    pub fn txns(&mut self) -> JournalReaderIter {
        JournalReaderIter {
            reader: self
        }
    }
}

pub struct JournalReaderIter<'a> {
    reader: &'a mut JournalReader
}

impl<'a> Iterator for JournalReaderIter<'a> {

    type Item = Result<Txn, JournalReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_txn() {
            Ok(Some(rec)) => Some(Ok(rec)),
            Ok(None) => None,
            Err(e) => Some(Err(e))
        }
    }
}

#[test]
fn test() {
    let mut parser = JournalReader::open("/home/brad/Downloads/db.find9.net.jnl").unwrap();
    parser.seek(2).unwrap();

    for txn in parser.txns() {
        println!("{:?}", txn);
    }
}
