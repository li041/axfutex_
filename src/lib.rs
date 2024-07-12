//! 支持 futex 相关的 syscall
#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(stmt_expr_attributes)]

extern crate alloc;

pub mod flags;
mod core;
pub mod waitwake;
