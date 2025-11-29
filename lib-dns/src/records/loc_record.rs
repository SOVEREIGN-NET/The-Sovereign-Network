use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::coord_utils::CoordUtils;

#[derive(Clone, Debug)]
pub struct LocRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) version: u8,
    pub(crate) size: u8,
    pub(crate) h_precision: u8,
    pub(crate) v_precision: u8,
    pub(crate) latitude: u32,
    pub(crate) longitude: u32,
    pub(crate) altitude: u32
}

impl Default for LocRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            version: 0,
            size: 0,
            h_precision: 0,
            v_precision: 0,
            latitude: 0,
            longitude: 0,
            altitude: 0
        }
    }
}

impl RecordBase for LocRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let version = buf[off+8];
        let size = buf[off+9];
        let h_precision = buf[off+10];
        let v_precision = buf[off+11];
        let latitude = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let longitude = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);
        let altitude = u32::from_be_bytes([buf[off+20], buf[off+21], buf[off+22], buf[off+23]]);

        Self {
            class,
            ttl,
            version,
            size,
            h_precision,
            v_precision,
            latitude,
            longitude,
            altitude
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 24];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf[9] = self.version;
        buf[10] = self.size;
        buf[11] = self.h_precision;
        buf[12] = self.v_precision;
        buf.splice(12..16, self.latitude.to_be_bytes());
        buf.splice(16..20, self.longitude.to_be_bytes());
        buf.splice(20..24, self.altitude.to_be_bytes());

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Loc
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl LocRecord {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn set_size(&mut self, size: u8) {
        self.size = size;
    }

    pub fn get_size(&self) -> u8 {
        self.size
    }

    pub fn set_h_precision(&mut self, h_precision: u8) {
        self.h_precision = h_precision;
    }

    pub fn get_h_precision(&self) -> u8 {
        self.h_precision
    }

    pub fn set_v_precision(&mut self, h_precision: u8) {
        self.v_precision = h_precision;
    }

    pub fn get_v_precision(&self) -> u8 {
        self.v_precision
    }
    
    pub fn set_latitude(&mut self, latitude: u32) {
        self.latitude = latitude;
    }
    
    pub fn get_latitude(&self) -> u32 {
        self.latitude
    }
    
    pub fn set_longitude(&mut self, longitude: u32) {
        self.longitude = longitude;
    }
    
    pub fn get_longitude(&self) -> u32 {
        self.longitude
    }
    
    pub fn set_altitude(&mut self, altitude: u32) {
        self.altitude = altitude;
    }
    
    pub fn get_altitude(&self) -> u32 {
        self.altitude
    }
}

impl fmt::Display for LocRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (lat_deg, lat_min, lat_sec, lat_dir) = self.latitude.to_coord(true);
        let (lon_deg, lon_min, lon_sec, lon_dir) = self.longitude.to_coord(false);
        let alt = (self.altitude as f64 - 100_000.0 * 100.0) / 100.0;

        write!(f, "{:<8}{:<8}{:<8}{} {} {:.3} {} {} {} {:.3} {} {:.2}m {:.2}m {:.2}m {:.2}m", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               lat_deg,
               lat_min,
               lat_sec,
               lat_dir,
               lon_deg,
               lon_min,
               lon_sec,
               lon_dir,
               alt,
               self.size as f64 / 100.0,
               self.h_precision as f64 / 100.0,
               self.v_precision as f64 / 100.0)
    }
}
