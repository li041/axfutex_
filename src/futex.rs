//! 实现与futex相关的系统调用
use alloc::collections::{BTreeMap, VecDeque};
use axsync::Mutex;
use axtask::{AxTaskRef, WaitQueue};

extern crate alloc;

/// vec中的元素分别是任务指针,对应存储时的futex变量的值
//pub static FUTEX_WAIT_TASK: Mutex<BTreeMap<FutexKey, VecDeque<(AxTaskRef, u32)>>> =
//    Mutex::new(BTreeMap::new());
pub static FUTEX_WAIT_TASK: Mutex<BTreeMap<FutexKey, VecDeque<FutexQ>>> =
    Mutex::new(BTreeMap::new());

/// waiting queue which stores tasks waiting for futex variable
pub static WAIT_FOR_FUTEX: WaitQueue = WaitQueue::new();

/// Futexes are matched on equal values of this key.
///
/// use pid to replace the mm_struct pointer
/// 
/// only support process private  and anonymous mapping now
#[derive(Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct FutexKey {
    /// use pid to replace the mm_struct pointer to distinguish different processes
    pub pid: u64,
    // aligned to page size addr
    aligned: usize,
    // offset in page
    offset: u32,
}

/// Kernel futex 
pub struct FutexQ {
    /// The `val` of the futex
    /// the task in the queue waiting for the same futex may have different `val`
    pub key: FutexKey,
    /// the task which is waiting for the futex
    pub task: AxTaskRef,
    /// the bitset of the futex
    pub bitset: u32,
}

impl FutexQ {
    /// Create a new futex queue
    pub fn new(key: FutexKey, task: AxTaskRef, bitset: u32) -> Self {
        Self { key, task, bitset}
    }
}


impl FutexKey {
    pub fn new(pid: u64, aligned: usize, offset: u32) -> Self {
        Self { pid, aligned, offset }
    }
}
#[derive(Default)]
/// 用于存储 robust list 的结构
pub struct FutexRobustList {
    /// The location of the head of the robust list in user space
    pub head: usize,
    /// The length of the robust list
    pub len: usize,
}

impl FutexRobustList {
    /// Create a new robust list
    pub fn new(head: usize, len: usize) -> Self {
        Self { head, len }
    }
}

pub fn clear_wait(id: u64, leader: bool) {
    let mut futex_wait_task = FUTEX_WAIT_TASK.lock();

    if leader {
        // 清空所有所属进程为指定进程的线程
        futex_wait_task.iter_mut().for_each(|(_, futex_qs)| {
            // tasks.drain_filter(|task| task.get_process_id() == id);
            futex_qs.retain(|futex_q| futex_q.key.pid != id);
        });
    } else {
        futex_wait_task.iter_mut().for_each(|(_, futex_qs)| {
            // tasks.drain_filter(|task| task.id().as_u64() == id);
            futex_qs.retain(|futex_q| futex_q.task.id().as_u64() != id)
        });
    }

    // 如果一个共享变量不会被线程所使用了，那么直接把他移除
    // info!("clean pre keys: {:?}", futex_wait_task.keys());
    futex_wait_task.retain(|_, futex_qs| !futex_qs.is_empty());
}