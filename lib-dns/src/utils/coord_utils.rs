use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoordError(String);

pub trait CoordUtils: Sized {

    fn to_coord(&self, is_lat: bool) -> (u8, u8, f64, char);

    fn from_coord(degrees: u8, minutes: u8, seconds: f64, dir: char) -> Result<Self, CoordError>;

    fn from_str_coord(s: &str) -> Result<Self, CoordError>;
}

impl fmt::Display for CoordError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CoordUtils for u32 {

    fn to_coord(&self, is_lat: bool) -> (u8, u8, f64, char) {
        let mut val = *self as i64 - (1 << 31);
        let dir = if is_lat {
            if val < 0 {
                val = -val;
                'S'

            } else {
                'N'
            }

        } else {
            if val < 0 {
                val = -val; 'W'

            } else {
                'E'
            }
        };

        let degrees = (val / 3_600_000) as u8;
        let minutes = ((val % 3_600_000) / 60_000) as u8;
        let seconds = ((val % 60_000) as f64) / 1000.0;
        (degrees, minutes, seconds, dir)
    }

    fn from_coord(degrees: u8, minutes: u8, seconds: f64, dir: char) -> Result<Self, CoordError> {
        let mut val = (degrees as i64) * 3_600_000
            + (minutes as i64) * 60_000
            + (seconds * 1000.0).round() as i64;

        match dir {
            'S' | 'W' => val = -val,
            'N' | 'E' => {}
            _ => return Err(CoordError(format!("invalid direction: {}", dir)))
        }

        Ok((val + (1 << 31)) as Self)
    }

    fn from_str_coord(s: &str) -> Result<Self, CoordError> {
        let parts: Vec<&str> = s.trim().split_whitespace().collect();
        if parts.len() != 4 {
            return Err(CoordError("length is too short".to_string()));
        }

        let degrees = parts[0].parse::<u8>().map_err(|_| CoordError("invalid degrees".to_string()))?;
        let minutes = parts[1].parse::<u8>().map_err(|_| CoordError("invalid degrees".to_string()))?;
        let seconds = parts[2].parse::<f64>().map_err(|_| CoordError("invalid seconds".to_string()))?;
        let dir = parts[3].chars().next().ok_or(CoordError("invalid direction".to_string()))?;

        Self::from_coord(degrees, minutes, seconds, dir)
    }
}

pub fn encode_loc_precision(s: &str) -> Result<u8, CoordError> {
    let val = s.strip_suffix('m').unwrap_or(s).parse::<f64>().map_err(|e| CoordError(e.to_string()))?;
    for exp in 0..=9 {
        for base in 0..=9 {
            let encoded = (base as f64) * 10f64.powi(exp);
            if (val - encoded).abs() < 0.5 {
                return Ok(((base << 4) | exp).try_into().map_err(|_| CoordError("unable to parse into u8".to_string()))?);
            }
        }
    }

    Err(CoordError(format!("cannot encode LOC precision from value: {}", s)))
}
