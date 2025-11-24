use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use crate::refresh::tasks::inter::task::Task;

pub struct RefreshHandler {
    //pub(crate) kademlia: Option<Box<dyn KademliaBase>>,
    tasks: Vec<Box<dyn Task>>,
    refresh_time: Arc<AtomicU64>,
    running: Arc<AtomicBool>
}

impl RefreshHandler {

    pub fn new() -> Self {
        Self {
            //kademlia: None,
            tasks: Vec::new(),
            refresh_time: Arc::new(AtomicU64::new(3600000)),
            running: Arc::new(AtomicBool::new(false))
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    //- we should probably just static the damn handler at this point....
    pub fn start(&self) {
        if self.is_running() {
            //panic or something...
            return;
        }

        self.running.store(true, Ordering::Relaxed);

        let handle = thread::spawn({
            let tasks = self.tasks.clone();
            let refresh_time = Arc::clone(&self.refresh_time);
            let running = Arc::clone(&self.running);
            move || {
                while running.load(Ordering::Relaxed) { //self.is_running()
                    sleep(Duration::from_millis(refresh_time.load(Ordering::SeqCst)));

                    for task in &tasks {
                        task.execute();
                    }
                }
            }
        });

        //handle.join().unwrap();
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn get_refresh_time(&self) -> u64 {
        self.refresh_time.load(Ordering::SeqCst)
    }

    pub fn set_refresh_time(&self, refresh_time: u64) {
        self.refresh_time.store(refresh_time, Ordering::SeqCst);
    }

    pub fn add_operation(&mut self, task: Box<dyn Task>) {
        self.tasks.push(task);
    }
}
