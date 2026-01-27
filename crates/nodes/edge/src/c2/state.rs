use std::sync::{Arc, Mutex, Condvar};
use std::time::{Duration, Instant};
use log::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemMode {
    /// Ghost Mode: Network silent, only C2 polling active.
    Ghost,
    /// Active Mode: P2P Swarm running, Local Discovery active.
    Active,
}

#[derive(Clone)]
pub struct CommandState {
    inner: Arc<StateInner>,
}

struct StateInner {
    mode: Mutex<SystemMode>,
    cvar: Condvar,
    last_activation: Mutex<Option<Instant>>,
}

impl CommandState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StateInner {
                mode: Mutex::new(SystemMode::Ghost),
                cvar: Condvar::new(),
                last_activation: Mutex::new(None),
            })
        }
    }

    /// Transition the system to a new mode.
    /// Returns true if the mode actually changed.
    pub fn set_mode(&self, new_mode: SystemMode) -> bool {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        if *mode_lock != new_mode {
            info!("[CommandState] Transitioning: {:?} -> {:?}", *mode_lock, new_mode);
            *mode_lock = new_mode;
            
            if new_mode == SystemMode::Active {
                if let Ok(mut last) = self.inner.last_activation.lock() {
                    *last = Some(Instant::now());
                }
            }
            
            // Notify all waiters (e.g. Network Thread)
            self.inner.cvar.notify_all();
            true
        } else {
            false
        }
    }

    /// Get current mode
    pub fn current_mode(&self) -> SystemMode {
        *self.inner.mode.lock().unwrap()
    }

    /// Block current thread until the system enters Active mode.
    /// If already Active, returns immediately.
    pub fn await_activation(&self) {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        while *mode_lock != SystemMode::Active {
            // Wait for notification
            mode_lock = self.inner.cvar.wait(mode_lock).unwrap();
        }
    }

    /// Block current thread until system enters Active mode OR timeout occurs.
    /// Returns true if Active, false if Timed Out.
    pub fn await_activation_timeout(&self, timeout: Duration) -> bool {
        let mut mode_lock = self.inner.mode.lock().unwrap();
        let start = Instant::now();
        
        while *mode_lock != SystemMode::Active {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return false;
            }
            let remaining = timeout - elapsed;
            let (new_lock, result) = self.inner.cvar.wait_timeout(mode_lock, remaining).unwrap();
            mode_lock = new_lock;
            if result.timed_out() && *mode_lock != SystemMode::Active {
                return false;
            }
        }
        true
    }
}
