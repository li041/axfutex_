use axhal::mem::VirtAddr;
use axlog::{info, debug};
use core::time::Duration;
use axprocess::{current_task, futex::WAIT_FOR_FUTEX, signal::current_have_signals, yield_now_task};
use axerrno::LinuxError;
use crate::futex::FutexQ;

use crate::core::{futex_get_value_locked, futex_hash, get_futex_key, FUTEXQUEUES};

pub type AxSyscallResult = Result<isize, axerrno::LinuxError>;



/// val3 is bitset
pub fn futex_wait(vaddr: VirtAddr, flags: i32, expected_val: u32, deadline: Option<Duration>, bitset: u32) -> AxSyscallResult {
    debug!("[futex_wait] vaddr: {:?}, flags: {:?}, val: {:?}, deadline: {:?}", vaddr, flags, expected_val, deadline);
    let mut is_tiemout = false;
    // we may be victim of spurious wakeups, so we need to loop
    loop {
        let key = get_futex_key(vaddr, flags);
        let real_futex_val = futex_get_value_locked(vaddr)?;
        if expected_val != real_futex_val as u32 {
            return Err(LinuxError::EAGAIN);
        }
        // 比较后相等，放入等待队列
        let mut hash_bucket= FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        let cur_futexq = FutexQ::new(key, current_task().as_task_ref().clone(), bitset);
        hash_bucket.push_back(cur_futexq);

        // drop lock to avoid deadlock
        drop(hash_bucket);

        if let Some(deadline) = deadline {
            is_tiemout = WAIT_FOR_FUTEX.wait_timeout(deadline);
        }
        else {
            // If timeout is NULL, the operation can block indefinitely.
            yield_now_task();
        }

        // If we were woken (and unqueued), we succeeded, whatever. 
        // We doesn't care about the reason of wakeup if we were unqueued.
        let mut hash_bucket= FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        if let Some(idx) = hash_bucket.iter().position(|futex_q| futex_q.match_key(&key)) {
            hash_bucket.remove(idx);
            if is_tiemout {
                return Err(LinuxError::ETIMEDOUT);
            }
            if current_have_signals() {
                return Err(LinuxError::EINTR);
            }
        }
        else {
            // the task is woken up anyway
            return Ok(0);
        }
    }
}


// no need to check the bitset, faster than futex_wake_bitset
pub fn futex_wake(vaddr: VirtAddr, flags: i32, nr_waken: u32) -> AxSyscallResult {
    info!("[futex_wake] vaddr: {:?}, flags: {:?}, nr_waken: {:?}", vaddr, flags, nr_waken);
    let mut ret = 0;
    let key = get_futex_key(vaddr, flags);
    let mut hash_bucket= FUTEXQUEUES.buckets[futex_hash(&key)].lock();
    if hash_bucket.is_empty() {
        return Ok(0);
    } 
    else {
        hash_bucket.retain(|futex_q| {
            if ret < nr_waken && futex_q.key == key {
                WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                ret += 1;
                return false;
            }
            true
        })
    }
    // drop hash_bucket to avoid deadlock 
    drop(hash_bucket);
    yield_now_task();
    Ok(ret as isize)
}

pub fn futex_wake_bitset(vaddr: VirtAddr, flags: i32, nr_waken: u32, bitset: u32) -> AxSyscallResult {
    info!("[futex_wake_bitset] vaddr: {:?}, flags: {:?}, nr_waken: {:?}, bitset: {:x}", vaddr, flags, nr_waken, bitset);
    if bitset == 0 {
        return Err(LinuxError::EINVAL);
    }
    let mut ret = 0;
    let key = get_futex_key(vaddr, flags);
    let mut hash_bucket= FUTEXQUEUES.buckets[futex_hash(&key)].lock();
    if hash_bucket.is_empty() {
        return Ok(0);
    } 
    else {
        hash_bucket.retain(|futex_q| {
            if ret == nr_waken {
                return true;
            }
            if (futex_q.bitset & bitset) != 0 && futex_q.key == key {
                WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                ret += 1;
                return false;
            }
            return true;
        })
    }
    // drop hash_bucket to avoid deadlock 
    drop(hash_bucket);
    yield_now_task();
    Ok(ret as isize)
}


pub fn futex_requeue(uaddr: VirtAddr, flags: i32, nr_waken: u32, uaddr2: VirtAddr, nr_requeue: u32) -> AxSyscallResult {
    let mut ret = 0;
    let mut requeued = 0;
    let key = get_futex_key(uaddr, flags);
    let req_key = get_futex_key(uaddr2, flags);

    if key == req_key {
        return futex_wake(uaddr, flags, nr_waken);
    } 



    let mut hash_bucket= FUTEXQUEUES.buckets[futex_hash(&key)].lock();
    if hash_bucket.is_empty() {
        return Ok(0);
    } 
    else {
        while let Some(futex_q) = hash_bucket.pop_front() {
            if futex_q.key == key {
                WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                ret += 1;
                if ret == nr_waken {
                    break;
                }
            }
        }
        if hash_bucket.is_empty() {
            return Ok(ret as isize);
        }
        // requeue the rest of the waiters
        let mut req_bucket = FUTEXQUEUES.buckets[futex_hash(&req_key)].lock();
        while let Some(futex_q) = hash_bucket.pop_front() {
            req_bucket.push_back(futex_q); 
            requeued += 1;
            if requeued == nr_requeue {
                break;
            }
        }
    }
    Ok(ret as isize)
}