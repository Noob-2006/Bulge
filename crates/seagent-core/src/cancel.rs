use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Cooperative cancellation shared between a session, its steps and its tools.
/// Children observe their parent: cancelling a parent cancels every child.
#[derive(Clone, Debug, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    parent: Option<Box<Cancel>>,
    deadline: Option<Instant>,
}

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn child(&self) -> Self {
        Cancel { flag: Arc::new(AtomicBool::new(false)), parent: Some(Box::new(self.clone())), deadline: None }
    }
    pub fn with_deadline(&self, at: Instant) -> Self {
        let mut c = self.child();
        c.deadline = Some(at);
        c
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        if self.flag.load(Ordering::SeqCst) {
            return true;
        }
        if let Some(d) = self.deadline {
            if Instant::now() >= d {
                return true;
            }
        }
        self.parent.as_ref().is_some_and(|p| p.is_cancelled())
    }
    pub fn timed_out(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parent_cancels_child_but_not_reverse() {
        let p = Cancel::new();
        let c = p.child();
        c.cancel();
        assert!(c.is_cancelled());
        assert!(!p.is_cancelled());
        let c2 = p.child();
        p.cancel();
        assert!(c2.is_cancelled());
    }

    #[test]
    fn deadline_expires() {
        let c = Cancel::new().with_deadline(Instant::now() + Duration::from_millis(10));
        assert!(!c.is_cancelled());
        std::thread::sleep(Duration::from_millis(20));
        assert!(c.is_cancelled());
        assert!(c.timed_out());
    }
}
