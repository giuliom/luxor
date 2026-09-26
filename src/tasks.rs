//! Long-running tasks that live as long as the server.
//!
//! A task is spawned with a [`Shutdown`] signal and is expected to return
//! soon after the signal fires. [`BackgroundTasks::shutdown`] fires it for
//! every task at once, once the server has stopped taking requests, and waits
//! a bounded time for them to finish; a task still running then is abandoned
//! with the process.

use std::{future::Future, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time::Instant};

/// Resolves once shutdown has been requested. Cloning it is cheap, so a task
/// can hand copies to the work it starts.
#[derive(Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// A signal and the switch that fires it, for code that runs one task
    /// outside a [`BackgroundTasks`] registry.
    pub fn channel() -> (ShutdownTrigger, Self) {
        let (sender, receiver) = watch::channel(false);
        (ShutdownTrigger(sender), Self(receiver))
    }

    /// Waits until shutdown is requested. Returns immediately if it already
    /// was, and also if the trigger is gone, since nothing could then ever
    /// request it and the owner has already been dropped.
    pub async fn requested(&mut self) {
        let _ = self.0.wait_for(|requested| *requested).await;
    }

    pub fn is_requested(&self) -> bool {
        *self.0.borrow()
    }
}

/// Fires a [`Shutdown`] signal.
pub struct ShutdownTrigger(watch::Sender<bool>);

impl ShutdownTrigger {
    pub fn fire(&self) {
        // `send_replace` stores the value even with no receiver left, which
        // `send` would refuse.
        self.0.send_replace(true);
    }

    pub fn subscribe(&self) -> Shutdown {
        Shutdown(self.0.subscribe())
    }
}

/// The tasks started alongside the server.
pub struct BackgroundTasks {
    trigger: ShutdownTrigger,
    running: Vec<(&'static str, JoinHandle<()>)>,
}

impl Default for BackgroundTasks {
    fn default() -> Self {
        let (trigger, _signal) = Shutdown::channel();
        Self {
            trigger,
            running: Vec::new(),
        }
    }
}

impl BackgroundTasks {
    /// Starts `task`, handing it the shared shutdown signal. `name` identifies
    /// the task in the shutdown logs.
    pub fn spawn<F, Fut>(&mut self, name: &'static str, task: F)
    where
        F: FnOnce(Shutdown) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(task(self.trigger.subscribe()));
        self.running.push((name, handle));
    }

    pub fn len(&self) -> usize {
        self.running.len()
    }

    pub fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Signals every task to stop and waits up to `grace` in total for them.
    pub async fn shutdown(self, grace: Duration) {
        self.trigger.fire();
        let deadline = Instant::now() + grace;
        for (name, handle) in self.running {
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(Ok(())) => tracing::info!(task = name, "background task stopped"),
                Ok(Err(error)) => {
                    tracing::error!(task = name, ?error, "background task failed");
                }
                Err(_) => tracing::warn!(
                    task = name,
                    "background task did not stop within the shutdown grace period"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn every_task_sees_the_shutdown_and_is_awaited() {
        let mut tasks = BackgroundTasks::default();
        let finished = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        for flag in &finished {
            let flag = flag.clone();
            tasks.spawn("waiter", move |mut shutdown| async move {
                shutdown.requested().await;
                flag.store(true, Ordering::SeqCst);
            });
        }
        assert_eq!(tasks.len(), 2);

        tasks.shutdown(Duration::from_secs(5)).await;
        assert!(finished.iter().all(|flag| flag.load(Ordering::SeqCst)));
    }

    /// A task that ignores the signal cannot hold the process hostage.
    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_no_longer_than_the_grace_period() {
        let mut tasks = BackgroundTasks::default();
        tasks.spawn("stubborn", |_shutdown| std::future::pending());
        let started = Instant::now();
        tasks.shutdown(Duration::from_secs(5)).await;
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(5) && waited < Duration::from_secs(6));
    }

    #[tokio::test]
    async fn a_signal_already_fired_resolves_at_once() {
        let (trigger, mut signal) = Shutdown::channel();
        assert!(!signal.is_requested());
        trigger.fire();
        signal.requested().await;
        assert!(signal.is_requested());
        // A late subscriber sees the request too.
        trigger.subscribe().requested().await;
    }
}
