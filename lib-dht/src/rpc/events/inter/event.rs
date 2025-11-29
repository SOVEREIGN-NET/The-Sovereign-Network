pub trait Event {

    fn is_prevent_default(&self) -> bool;

    fn prevent_default(&mut self);
}
