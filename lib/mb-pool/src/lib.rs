//! Generic per-key async connection pool.

use async_trait::async_trait;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("connect failed: {0}")]
    Connect(String),
}

#[async_trait]
pub trait ConnectionFactory: Send + Sync + 'static {
    type Conn: Send + 'static;
    type Key: Eq + Hash + Clone + Send + Sync + 'static;
    async fn connect(&self, key: &Self::Key) -> Result<Self::Conn, PoolError>;
}

struct Slot<C> {
    conn: C,
    last_used: Instant,
}

type PoolMap<K, C> = Arc<Mutex<HashMap<K, Vec<Slot<C>>>>>;

pub struct Pool<F: ConnectionFactory> {
    factory: F,
    max_per_key: usize,
    idle_timeout: Duration,
    inner: PoolMap<F::Key, F::Conn>,
}

impl<F: ConnectionFactory> Pool<F> {
    pub fn new(factory: F, max_per_key: usize, idle_timeout: Duration) -> Self {
        Self {
            factory,
            max_per_key,
            idle_timeout,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub async fn acquire(&self, key: &F::Key) -> Result<Pooled<F>, PoolError> {
        {
            let mut map = self.inner.lock().await;
            if let Some(slots) = map.get_mut(key) {
                while let Some(slot) = slots.pop() {
                    if slot.last_used.elapsed() < self.idle_timeout {
                        return Ok(Pooled {
                            conn: Some(slot.conn),
                            key: key.clone(),
                            pool: self.inner.clone(),
                            max: self.max_per_key,
                        });
                    }
                }
            }
        }
        let conn = self.factory.connect(key).await?;
        Ok(Pooled {
            conn: Some(conn),
            key: key.clone(),
            pool: self.inner.clone(),
            max: self.max_per_key,
        })
    }
}

pub struct Pooled<F: ConnectionFactory> {
    conn: Option<F::Conn>,
    key: F::Key,
    pool: PoolMap<F::Key, F::Conn>,
    max: usize,
}

impl<F: ConnectionFactory> std::ops::Deref for Pooled<F> {
    type Target = F::Conn;
    fn deref(&self) -> &Self::Target {
        self.conn
            .as_ref()
            .expect("Pooled: connection already returned")
    }
}

impl<F: ConnectionFactory> std::ops::DerefMut for Pooled<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn
            .as_mut()
            .expect("Pooled: connection already returned")
    }
}

impl<F: ConnectionFactory> Drop for Pooled<F> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let pool = self.pool.clone();
            let key = self.key.clone();
            let max = self.max;
            tokio::spawn(async move {
                let mut map = pool.lock().await;
                let slots = map.entry(key).or_default();
                if slots.len() < max {
                    slots.push(Slot {
                        conn,
                        last_used: Instant::now(),
                    });
                }
            });
        }
    }
}
