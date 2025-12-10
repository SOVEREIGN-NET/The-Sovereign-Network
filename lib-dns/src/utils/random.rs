use std::time::{SystemTime, UNIX_EPOCH};
use std::mem;

pub fn gen<T>() -> T
where
    T: Default + Copy,
{
    let mut rng = Lcg::new(seed());
    rng.gen_num::<T>()
}

pub fn gen_array<T, const N: usize>() -> [T; N]
where
    T: Default + Copy,
{
    let mut rng = Lcg::new(seed());
    let mut array = [T::default(); N];
    for i in 0..N {
        array[i] = rng.gen_num::<T>();
    }
    array
}

fn seed() -> u64 {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_nanos() as u64
}

struct Lcg {
    seed: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg { seed }
    }

    fn gen_num<T>(&mut self) -> T
    where
        T: Default + Copy,
    {
        const A: u64 = 6364136223846793005;
        const C: u64 = 1;
        self.seed = self.seed.wrapping_mul(A).wrapping_add(C);

        let bytes = self.seed.to_le_bytes();
        let mut result = T::default();

        // Cast the bytes to the target type
        let result_ptr = &mut result as *mut T as *mut u8;
        let size = mem::size_of::<T>();

        // Copy the appropriate number of bytes into result
        unsafe {
            result_ptr.copy_from_nonoverlapping(bytes.as_ptr(), size);
        }

        result
    }
}
