use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChangeEvent {
    pub path: PathBuf,
}

pub struct FileChangeListener {
    receiver: mpsc::Receiver<FileChangeEvent>,
    shutdown: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl FileChangeListener {
    pub async fn next_event(&mut self) -> Option<FileChangeEvent> {
        self.receiver.recv().await
    }

    #[cfg(test)]
    pub async fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = tokio::task::spawn_blocking(move || task.join()).await;
        }
    }
}

impl Drop for FileChangeListener {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

pub fn watch_file(path: impl Into<PathBuf>) -> FileChangeListener {
    watch_file_with_interval(path, DEFAULT_POLL_INTERVAL)
}

pub fn watch_file_with_interval(
    path: impl Into<PathBuf>,
    poll_interval: Duration,
) -> FileChangeListener {
    let path = path.into();
    let initial_signature = file_signature_sync(&path);
    let (tx, receiver) = mpsc::channel(32);
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let task = thread::spawn(move || {
        let mut last_signature = initial_signature;
        while !thread_shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(poll_interval);
            if thread_shutdown.load(Ordering::SeqCst) {
                break;
            }
            let next_signature = file_signature_sync(&path);
            if next_signature != last_signature {
                let _ = tx.blocking_send(FileChangeEvent { path: path.clone() });
                last_signature = next_signature;
            }
        }
    });

    FileChangeListener {
        receiver,
        shutdown,
        task: Some(task),
    }
}

fn file_signature_sync(path: &Path) -> Option<u64> {
    match std::fs::read(path) {
        Ok(content) => Some(hash_bytes(&content)),
        Err(_) => None,
    }
}

fn hash_bytes(input: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::timeout;

    fn temp_file(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "livereload_{}_{}_{}",
            name,
            std::process::id(),
            nonce
        ))
    }

    #[tokio::test]
    async fn emits_when_file_content_changes() {
        let file = temp_file("changes");
        tokio::fs::write(&file, b"one")
            .await
            .expect("initial file should be written");

        let mut listener = watch_file_with_interval(&file, Duration::from_millis(20));
        tokio::fs::write(&file, b"two")
            .await
            .expect("updated file should be written");

        let event = timeout(Duration::from_secs(2), listener.next_event())
            .await
            .expect("event should arrive")
            .expect("listener should still be running");
        assert_eq!(event.path, file);

        listener.shutdown().await;
        let _ = tokio::fs::remove_file(&event.path).await;
    }

    #[tokio::test]
    async fn does_not_emit_when_content_unchanged() {
        let file = temp_file("same");
        tokio::fs::write(&file, b"stable")
            .await
            .expect("initial file should be written");

        let mut listener = watch_file_with_interval(&file, Duration::from_millis(20));
        tokio::fs::write(&file, b"stable")
            .await
            .expect("rewrite should succeed");

        let result = timeout(Duration::from_millis(200), listener.next_event()).await;
        assert!(
            result.is_err(),
            "no event should be emitted for same content"
        );

        listener.shutdown().await;
        let _ = tokio::fs::remove_file(&file).await;
    }
}
