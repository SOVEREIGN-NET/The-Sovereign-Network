pub trait CoordUtils {

    fn to_coord(&self, is_lat: bool) -> (u8, u8, f64, char);

    fn from_coord(degrees: u8, minutes: u8, seconds: f64, dir: char) -> u32;

    fn from_str_coord(s: &str) -> Option<u32>;
}

impl CoordUtils for u32 {

    fn to_coord(&self, is_lat: bool) -> (u8, u8, f64, char) {
        let mut val = *self as i64 - (1 << 31);
        let dir = if is_lat {
            if val < 0 { val = -val; 'S' } else { 'N' }
        } else {
            if val < 0 { val = -val; 'W' } else { 'E' }
        };
        let degrees = (val / 3_600_000) as u8;
        let minutes = ((val % 3_600_000) / 60_000) as u8;
        let seconds = ((val % 60_000) as f64) / 1000.0;
        (degrees, minutes, seconds, dir)
    }

    fn from_coord(degrees: u8, minutes: u8, seconds: f64, dir: char) -> Self {
        let mut val = (degrees as i64) * 3_600_000
            + (minutes as i64) * 60_000
            + (seconds * 1000.0).round() as i64;

        match dir {
            'S' | 'W' => val = -val,
            'N' | 'E' => {}
            _ => panic!("Invalid direction: {}", dir),
        }

        (val + (1 << 31)) as Self
    }

    fn from_str_coord(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split_whitespace().collect();
        if parts.len() != 4 {
            return None;
        }

        let degrees = parts[0].parse::<u8>().ok()?;
        let minutes = parts[1].parse::<u8>().ok()?;
        let seconds = parts[2].parse::<f64>().ok()?;
        let dir = parts[3].chars().next()?;

        Some(Self::from_coord(degrees, minutes, seconds, dir))
    }
}
