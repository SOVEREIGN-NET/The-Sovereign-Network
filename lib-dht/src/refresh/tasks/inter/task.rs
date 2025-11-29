pub trait Task: Send {

    fn execute(&self);

    fn clone_dyn(&self) -> Box<dyn Task>;
}

impl Clone for Box<dyn Task> {

    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}
