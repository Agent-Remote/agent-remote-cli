//! Retain one command's Ctrl-C across preparation, journaling, submission and waiting.

use std::future::{poll_fn, Future};
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::Poll;

use tokio::sync::watch;

tokio::task_local! {
    static RESULT_STARTED: Arc<AtomicBool>;
    static SIGNAL: watch::Receiver<Option<Result<(), io::ErrorKind>>>;
}

struct Listener(tokio::task::JoinHandle<()>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn scope<T>(work: impl Future<Output = T>) -> T {
    let (send, receive) = watch::channel(None);
    let mut signal = Box::pin(tokio::signal::ctrl_c());
    // Register before work starts. Keep that exact future alive across every phase transition.
    let first = poll_fn(|context| Poll::Ready(signal.as_mut().poll(context))).await;
    let listener = Listener(tokio::spawn(async move {
        let result = match first {
            Poll::Ready(result) => result,
            Poll::Pending => signal.await,
        };
        send.send_replace(Some(result.map_err(|error| error.kind())));
    }));
    let result = RESULT_STARTED
        .scope(
            Arc::new(AtomicBool::new(false)),
            SIGNAL.scope(receive, work),
        )
        .await;
    drop(listener);
    result
}

pub(super) async fn cancelled() -> io::Result<()> {
    let Ok(mut receiver) = SIGNAL.try_with(Clone::clone) else {
        return tokio::signal::ctrl_c().await;
    };
    loop {
        if let Some(result) = *receiver.borrow() {
            return result.map_err(io::Error::from);
        }
        if receiver.changed().await.is_err() {
            return Err(io::Error::other("skill interrupt listener stopped"));
        }
    }
}

pub(super) fn is_cancelled() -> bool {
    SIGNAL
        .try_with(|receiver| receiver.borrow().is_some())
        .unwrap_or(false)
}

pub(super) fn mark_result_started() {
    let _ = RESULT_STARTED.try_with(|started| started.store(true, Ordering::Relaxed));
}

pub(super) fn result_started() -> bool {
    RESULT_STARTED
        .try_with(|started| started.load(Ordering::Relaxed))
        .unwrap_or(false)
}

/// Preparation cancellation reports once, without contending for a detached review writer.
pub(super) async fn report(
    message: &'static str,
    object_id: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    if !json || result_started() {
        return Err(super::SkillExit(130).into());
    }
    let error = super::remote_result::failure("SKILL_INTERRUPTED", message, object_id);
    super::output::finish(json, move || {
        super::print_failure(&error, true);
        Err(super::SkillExit(130).into())
    })
    .await
}
