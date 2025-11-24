use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom};
use crate::journal::inter::txn_op_codes::TxnOpCodes;
use crate::journal::txn::Txn;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::unpack_fqdn;

#[derive(Debug, PartialEq, Eq)]
struct JournalHeader {
    begin_serial: u32,
    begin_offset: u32,
    end_serial: u32,
    end_offset: u32,
    index_size: u32,
    source_serial: u32,
    flags: u8
}

pub struct JournalReader {
    reader: BufReader<File>,
    header: Option<JournalHeader>
}

impl JournalReader {

    pub fn open(file_path: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            header: None
        })
    }

    pub fn iter(&mut self) -> JournalReaderIter {
        JournalReaderIter {
            parser: self
        }
    }

    pub fn parse_record(&mut self) -> Option<Txn> {
        if self.header == None {
            let mut buf = vec![0u8; 64];
            self.reader.read_exact(&mut buf).unwrap();

            // Magic (first 16 bytes): ";BIND LOG V9\n" or ";BIND LOG V9.2\n"
            let magic = true;//&buf[0..16];
            let v9 = b";BIND LOG V9\n";
            let v92 = b";BIND LOG V9.2\n";
            //if !(magic.starts_with(v9) || magic.starts_with(v92)) {
            //    //return Err(io::Error::new(io::ErrorKind::InvalidData, "bad .jnl magic"));
            //}

            //let is_v92 = magic.starts_with(v92);

            self.header = Some(JournalHeader {
                begin_serial: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
                begin_offset: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
                end_serial: u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
                end_offset: u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]),
                index_size: u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]),
                source_serial: u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
                flags: buf[40]
            });

            //println!("V9 {}", is_v92);
            println!("Begin Serial {}", self.header.as_ref()?.begin_serial);
            println!("Begin Offset {}", self.header.as_ref()?.begin_offset);
            println!("End Serial {}", self.header.as_ref()?.end_serial);
            println!("End Offset {}", self.header.as_ref()?.end_offset);
            println!("Index Size {}", self.header.as_ref()?.index_size);
            println!("Source Serial {}", self.header.as_ref()?.source_serial);
            println!("Flags {}", self.header.as_ref()?.flags);

            // ===== 2) OPTIONAL INDEX =====
            // Each index entry is 8 bytes: [serial(4) | offset(4)]
            self.reader.seek(SeekFrom::Current((self.header.as_ref()?.index_size as i64) * 8)).unwrap();

            // ===== 3) POSITION TO FIRST TRANSACTION =====
            self.reader.seek(SeekFrom::Start(self.header.as_ref()?.begin_offset as u64)).unwrap();
        }

        let magic = true;

        if self.reader.stream_position().unwrap() >= self.header.as_ref()?.end_offset as u64 {
            return None;
        }

        let (size, rr_count, serial_0, serial_1) = match magic {
            true => {
                let mut buf = vec![0u8; 16];
                self.reader.read_exact(&mut buf).unwrap();
                let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let rr_count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let serial_0 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let serial_1 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                (size, Some(rr_count), serial_0, serial_1)
            }
            false => {
                let mut buf = vec![0u8; 12];
                self.reader.read_exact(&mut buf).unwrap();
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
            self.reader.read_exact(&mut buf).unwrap();
            let rr_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            remaining -= 4 + rr_len;

            buf = vec![0u8; rr_len as usize];
            self.reader.read_exact(&mut buf).unwrap();

            let mut off = 0;

            let (name, length) = unpack_fqdn(&buf, off);
            off += length;

            let _type = RRTypes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();

            if _type == RRTypes::Soa {
                seen_soa += 1;

                if seen_soa == 2 {
                    phase = TxnOpCodes::Add;
                }

                continue;
            }

            let record = <dyn RecordBase>::from_wire(_type, &buf, off+2).unwrap();
            txn.add_record(phase, &name, record);
        }

        Some(txn)
    }
}

pub struct JournalReaderIter<'a> {
    parser: &'a mut JournalReader
}

impl<'a> Iterator for JournalReaderIter<'a> {

    type Item = Txn;

    fn next(&mut self) -> Option<Self::Item> {
        self.parser.parse_record()
    }
}
