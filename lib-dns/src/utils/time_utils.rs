pub trait TimeUtils {

    fn to_time_format(&self) -> String;

    fn from_time_format(s: &str) -> u32;
}

impl TimeUtils for u32 {

    fn to_time_format(&self) -> String {
        let mut seconds = *self;
        let sec = seconds % 60;
        seconds /= 60;
        let min = seconds % 60;
        seconds /= 60;
        let hour = seconds % 24;
        let days = seconds / 24;

        let (year, month, day) = date_from_days_since_epoch(days);

        format!("{:04}{:02}{:02}{:02}{:02}{:02}", year, month, day, hour, min, sec)
    }

    fn from_time_format(s: &str) -> Self {
        let year = s[0..4].parse::<i32>().unwrap();
        let month = s[4..6].parse::<u32>().unwrap();
        let day = s[6..8].parse::<u32>().unwrap();
        let hour = s[8..10].parse::<u32>().unwrap();
        let min = s[10..12].parse::<u32>().unwrap();
        let sec = s[12..14].parse::<u32>().unwrap();

        let days = days_since_unix_epoch(year, month, day);
        let total_seconds = days * 86400 + hour * 3600 + min * 60 + sec;

        total_seconds
    }
}

fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> u32 {
    let mut y = year;
    let mut m = month as i32;

    if m <= 2 {
        y -= 1;
        m += 12;
    }

    let a = y / 100;
    let b = a / 4;
    let c = 2 - a + b;
    let e = (365.25 * (y as f64 + 4716.0)) as i32;
    let f = (30.6001 * (m as f64 + 1.0)) as i32;

    let jd = c + day as i32 + e + f - 1524;
    (jd - 2440588) as u32
}

fn date_from_days_since_epoch(days: u32) -> (i32, u32, u32) {
    let jd = days as i32 + 2440588;

    let a = jd + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (b * 146097) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;

    let day = e - (153 * m + 2) / 5 + 1;
    let month = (m + 2) % 12 + 1;
    let year = b * 100 + d - 4800 + (m / 10);

    (year, month as u32, day as u32)
}
