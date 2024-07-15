use axsync::Mutex;
use hashbrown::HashMap;
use jhash;
use crate::futex::{FutexKey, FutexQ};

/* 
pub struct HashBuckets 
{
    buckets: Vec<Mutex<HashMap<K, V>>>,
    num_buckets: usize,
}

impl <K, V> HashBuckets<K, V>
where
    K: Hash + Eq,
{
    fn new(num_buckets: usize) -> Self {
        HashBuckets {
            buckets: (0..num_buckets).map(|_| Mutex::new(HashMap::new())).collect(),
            num_buckets,
        }
    }

    fn get(&self, key: &K) -> Option<V> 
    where 
        V: Clone,
    {
        let bucket = self.buckets[key.hash() % self.num_buckets].lock();
        bucket.get(key).cloned()
    }
}
    */

