use async_trait::async_trait;
use mb_pool::{ConnectionFactory, Pool, PoolError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

struct CounterFactory(Arc<AtomicU32>);

#[async_trait]
impl ConnectionFactory for CounterFactory {
    type Conn = u32;
    type Key = String;
    async fn connect(&self, _key: &Self::Key) -> Result<Self::Conn, PoolError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

#[tokio::test]
async fn reuses_connection() {
    let counter = Arc::new(AtomicU32::new(0));
    let pool: Pool<CounterFactory> = Pool::new(
        CounterFactory(counter.clone()),
        4,
        std::time::Duration::from_secs(60),
    );
    let c1 = pool
        .acquire(&"k1".to_string())
        .await
        .expect("acquire first connection");
    drop(c1);
    // Give the spawned return task a moment to run
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let c2 = pool
        .acquire(&"k1".to_string())
        .await
        .expect("acquire second connection");
    assert_eq!(*c2, 0, "should reuse first connection");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn isolates_by_key() {
    let counter = Arc::new(AtomicU32::new(0));
    let pool: Pool<CounterFactory> = Pool::new(
        CounterFactory(counter.clone()),
        4,
        std::time::Duration::from_secs(60),
    );
    let _ = pool.acquire(&"a".to_string()).await.expect("acquire a");
    let _ = pool.acquire(&"b".to_string()).await.expect("acquire b");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}
