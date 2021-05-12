/// Arch riscv

pub mod vcpu;
pub mod gdb;
pub mod consts;

use log::debug;
use crate::linux::uhyve::{UhyveNetwork, MmapMemory};
use crate::vm::Parameter;
use kvm_ioctls::VmFd;
use crate::error::*;

pub fn uhyve_init(vm: &VmFd, specs: &Parameter, mem: &MmapMemory) -> Result<Option<UhyveNetwork>>{
	debug!("riscv arch_init");
	Ok(Option::None)
}