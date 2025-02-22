use alloc::collections::VecDeque;
use alloc::boxed::Box;
use alloc::vec::Vec;
use axhal::mem::VirtAddr;
use axprocess::current_process;
use axerrno::LinuxError;
use axlog::info;
use crate::futex::{FutexKey, FutexQ};

use crate::waitwake::AxSyscallResult;

use super::flags::FLAGS_SHARED;
use crate::jhash::jhash2;
use axsync::Mutex;
use lazy_static::lazy_static;

/// the number of hash buckets, must be a power of 2
const FUTEX_HASH_SIZE: usize = 256;

lazy_static! {
    // can only hold the mutex through `futex_hash_bucket`
   pub static ref FUTEXQUEUES: FutexQueues = {
        info!("Initializing futex queues");
        let futex_queues = FutexQueues::new(FUTEX_HASH_SIZE);
        futex_queues
   };
}

/// the outer vector is the bucket, the inner vector is the futex queue
pub struct FutexQueues {
    pub buckets: Box<[Mutex<VecDeque<FutexQ>>]>,
}

impl FutexQueues {
    fn new(size: usize) -> Self {
        let mut buckets = Vec::with_capacity(size);
        for _ in 0..size {
            buckets.push(Mutex::new(VecDeque::new()));
        }
        Self {
            buckets: buckets.into_boxed_slice(),
        }         
    }
}

pub fn futex_hash(futex_key: &FutexKey) -> usize{
    let key = &[futex_key.pid, futex_key.aligned, futex_key.offset];
    let hash = jhash2(key, key[2]);
    let index = hash as usize & (FUTEX_HASH_SIZE - 1);
    index
}



pub fn futex_get_value_locked(vaddr: VirtAddr) -> AxSyscallResult {
    let process = current_process();
    if process.manual_alloc_for_lazy(vaddr).is_ok() {
        let real_futex_val = unsafe { (vaddr.as_usize() as *const u32).read_volatile() };
        Ok(real_futex_val as isize)
    }
    else {
        Err(LinuxError::EFAULT)
    }
}

pub fn get_futex_key(uaddr: VirtAddr, flags: i32) -> FutexKey {
    if flags & FLAGS_SHARED != 0 {
        /* Todo: after implement inode layer 
        let inode = uaddr.get_inode();
        let page_index = uaddr.get_page_index();
        let offset = uaddr.get_offset();
        FutexKey::new(inode, page_index, offset)
        */
        let pid = current_process().pid();
        let aligned = uaddr.align_down_4k().as_usize();
        let offset = uaddr.align_offset_4k() as u32;
        return FutexKey::new(pid, aligned, offset);
    }
    else {
        let pid = current_process().pid();
        let aligned = uaddr.align_down_4k().as_usize();
        let offset = uaddr.align_offset_4k() as u32;
        return FutexKey::new(pid, aligned, offset);
    } 
}