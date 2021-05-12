use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd};
use libc::ioctl;
use rustc_serialize::hex::ToHex;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::slice;
use crate::linux::arch::riscv::consts::*;

//use crate::arch::x86;
use crate::error::{self, Error::OsError};
use crate::gdb_parser::{
	Breakpoint, Error, FileData, Handler, Id, MemoryRegion, ProcessInfo, ProcessType, StopReason,
	ThreadId, VCont, VContFeature, Watchpoint,
};
use crate::linux::arch::vcpu::UhyveCPU;
use crate::utils::get_max_subslice;
use crate::vm::VirtualCPU;
use log::{debug, error, info};

/// Debugging Stub for linux/x64
/// Currently supported features:
/// - Register read/write
/// - Memory read/write
/// - Software breakpoints (int3)
/// - Hardware breakpoints
///    - Execute / Write / Read-Write
/// - Singlestepping / Continue
/// - LLDB support (transmit info about arch/reg layout)
///    - read of feature target.xml [i386-64bit.xml]
///    - qHostInfo triple sends x86_64-unknown-hermit

const INT3: &[u8] = &[0xcc];

impl UhyveCPU {
	/// Called on Trap. Creates Handler.
	/// Enter gdb-event-loop until gdb tells us to continue. Set singlestep mode if necessary and return
	// pub fn gdb_handle_exception<'a>(&mut self, signal: Option<VcpuExit<'a>>) {
	// 	debug!("Handling debug exception!");
	// 	if let Some(dbg) = &mut self.dbg {
	// 		let dbgarc = dbg.clone();
	// 		let dbg = dbgarc.lock().expect("No gdb available!");

	// 		let (mut cmdhandler, signal) = if let Some(signal) = signal {
	// 			// send signal with which we are stopped. Hardcoded to 5 for now (TODO)
	// 			(
	// 				CmdHandler::new(self, &dbg.state, signal),
	// 				Some(StopReason::Signal(5)),
	// 			)
	// 		} else {
	// 			// target stopped on boot. No signal recv'd yet. Pretend debug singal..? Not used rn anyways
	// 			(CmdHandler::new(self, &dbg.state, VcpuExit::Debug), None)
	// 		};

	// 		// enter command-handler, stay there until we receive a continue signal
	// 		let vcont = dbg
	// 			.handle_commands(&mut cmdhandler, signal)
	// 			.unwrap_or_else(|error| {
	// 				error!("Cannot handle debugging commands: {:?}", error);
	// 				// always continue
	// 				VCont::Continue
	// 			});

	// 		let hwbr = dbg.state.borrow().get_hardware_breakpoints();

	// 		// handler returned with a continuation command,
	// 		// determine if we should continue single-stepped or until next trap
	// 		match vcont {
	// 			VCont::Continue | VCont::ContinueWithSignal(_) => {
	// 				info!("Continuing execution..");
	// 				self.kvm_change_guestdbg(false, hwbr.as_ref())
	// 					.expect("Could not change KVM debugging state"); // TODO: optimize this, dont call too often?
	// 			}
	// 			VCont::Step | VCont::StepWithSignal(_) => {
	// 				info!("Starting Single Stepping..");
	// 				self.kvm_change_guestdbg(true, hwbr.as_ref())
	// 					.expect("Could not change KVM debugging state"); // TODO: optimize this, dont call too often?
	// 			}
	// 			_ => error!("Unknown Handler exit reason!"),
	// 		}
	// 	} else {
	// 		info!("Debugging disabled, ignoring exception {:?}.", signal);
	// 	};
	// }

	unsafe fn read_mem(&self, guest_addr: usize, len: usize) -> &[u8] {
		let phys = self.virt_to_phys(guest_addr);
		let host = self.host_address(phys);

		slice::from_raw_parts(host as *mut u8, len)
	}

	unsafe fn write_mem(&self, guest_addr: usize, data: &[u8]) {
		let phys = self.virt_to_phys(guest_addr);
		let host = self.host_address(phys);

		let mem: &mut [u8] = slice::from_raw_parts_mut(host as *mut u8, data.len());

		mem.copy_from_slice(data);
	}

	// fn kvm_change_guestdbg(
	// 	&mut self,
	// 	single_step: bool,
	// 	hwbr: Option<&x86::HWBreakpoints>, /*&HashMap<usize, Breakpoint>*/
	// ) -> Result<(), error::Error> {
	// 	debug!("KVM: Enable guest debug. SS:{}", single_step);
	// 	let mut dbg = kvm_guest_debug {
	// 		control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, // KVM_GUESTDBG_USE_HW_BP
	// 		pad: 0,
	// 		arch: kvm_guest_debug_arch { debugreg: [0; 8] },
	// 	};

	// 	if single_step {
	// 		dbg.control |= KVM_GUESTDBG_SINGLESTEP;
	// 	}

	// 	error!("Setting guestdbg");
	// 	if let Some(hwbr) = hwbr {
	// 		// arch.debugreg has 4 address registers (0-3), a control reg (7) and status reg (6). 4-5 are unused.
	// 		dbg.control |= KVM_GUESTDBG_USE_HW_BP;
	// 		for i in 0..4 {
	// 			dbg.arch.debugreg[i] = hwbr.get_addr(i).unwrap();
	// 		}
	// 		dbg.arch.debugreg[7] = hwbr.get_dr7();
	// 	}

	// 	let ret = unsafe {
	// 		ioctl(
	// 			self.get_vcpu().as_raw_fd(),
	// 			0x4048_ae9b, /* KVM_SET_GUEST_DEBUG, from https://android.googlesource.com/platform/system/sepolicy/+/master/public/ioctl_defines */
	// 			&dbg,
	// 		)
	// 	};
	// 	if ret < 0 {
	// 		return Err(OsError(unsafe { *libc::__errno_location() }));
	// 	}

	// 	Ok(())
	// }
}

pub struct State {
	breakpoints: HashMap<usize, SWBreakpoint>,
	breakpoints_hw: HashMap<usize, HWBreakpoint>,
}

#[derive(Debug)]
enum BreakpointKind {
	Breakpoint,
	WatchWrite,
	WatchAccess,
}

#[derive(Debug)]
struct SWBreakpoint {
	bp: Breakpoint,
	insn: u8,
}

#[derive(Debug)]
struct HWBreakpoint {
	kind: BreakpointKind,
	addr: u64,
	n_bytes: u64,
}

impl State {
	pub(crate) fn new() -> Self {
		Self {
			breakpoints: HashMap::new(),
			breakpoints_hw: HashMap::new(),
		}
	}

	// pub fn get_hardware_breakpoints(&self) -> Option<x86::HWBreakpoints> {
	// 	if self.breakpoints_hw.is_empty() {
	// 		return None;
	// 	}

	// 	if self.breakpoints_hw.len() > 4 {
	// 		error!("Cannot set more than 4 hardware breakpoints!")
	// 	}

	// 	let mut hwbr = x86::HWBreakpoints::default();

	// 	for (i, (addr, bp)) in self.breakpoints_hw.iter().take(4).enumerate() {
	// 		hwbr.0[i].addr = *addr as _;
	// 		hwbr.0[i].is_local = true;
	// 		hwbr.0[i].is_global = true;
	// 		hwbr.0[i].trigger = match bp.kind {
	// 			BreakpointKind::Breakpoint => x86::BreakTrigger::Ex,
	// 			BreakpointKind::WatchWrite => x86::BreakTrigger::W,
	// 			BreakpointKind::WatchAccess => x86::BreakTrigger::RW,
	// 		};
	// 		hwbr.0[i].size = match bp.n_bytes {
	// 			1 => x86::BreakSize::B1,
	// 			2 => x86::BreakSize::B2,
	// 			4 => x86::BreakSize::B4,
	// 			8 => x86::BreakSize::B8,
	// 			_ => {
	// 				error!("Unknown watchpoint size!");
	// 				x86::BreakSize::B1
	// 			}
	// 		};
	// 	}

	// 	Some(hwbr)
	// }
}

pub struct CmdHandler<'a> {
	// use RefCells to not break existing api of gdb_parser (no mutability in handler)
	resume: RefCell<Option<VCont>>,
	current_cpu: RefCell<&'a mut UhyveCPU>,
	state: &'a RefCell<State>,
	_current_signal: VcpuExit<'a>,
}

impl<'a> CmdHandler<'a> {
	pub fn new(
		cpu: &'a mut UhyveCPU,
		state: &'a RefCell<State>,
		signal: VcpuExit<'a>,
	) -> CmdHandler<'a> {
		CmdHandler {
			resume: RefCell::new(None),
			current_cpu: RefCell::new(cpu),
			_current_signal: signal,
			state,
		}
	}

	pub fn continue_execution(&self, reason: VCont) {
		debug!("Continuing..");
		*self.resume.borrow_mut() = Some(reason);
	}

	fn register_hardware_trap(&self, bp: HWBreakpoint) -> Result<(), Error> {
		{
			let brhw = &self.state.borrow().breakpoints_hw;
			// bail if breakpoint already exists
			if brhw.contains_key(&(bp.addr as _)) {
				return Err(Error::Error(6));
			}

			if brhw.len() >= 4 {
				error!("Cannot set more than 4 hardware breakpoints!");
				return Err(Error::Error(6));
			}
		}

		// HW BREAKPOINTS get set/removed during KVM update on cmd-loop exit! (kvm_change_guestdbg)

		self.state
			.borrow_mut()
			.breakpoints_hw
			.insert(bp.addr as _, bp);
		info!(
			"Add breakpoints_hw: {:?}",
			self.state.borrow().breakpoints_hw
		);
		Ok(())
	}

	fn deregister_hardware_trap(&self, breakpoint: HWBreakpoint) -> Result<(), Error> {
		info!(
			"Remove breakpoints_hw: {:?}",
			self.state.borrow().breakpoints_hw
		);
		if let Some(_bp) = self
			.state
			.borrow_mut()
			.breakpoints_hw
			.remove(&(breakpoint.addr as _))
		{
			// HW BREAKPOINTS get set/removed during KVM update on cmd-loop exit! (kvm_change_guestdbg)

			Ok(())
		} else {
			Err(Error::Error(4))
		}
	}
}

impl<'a> Handler for CmdHandler<'a> {
	fn should_cont(&self) -> Option<VCont> {
		self.resume.borrow().clone()
	}

	fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error> {
		Ok(ProcessType::Attached)
	}

	fn halt_reason(&self) -> Result<StopReason, Error> {
		//Ok(StopReason::Exited(23, 0))
		// TODO make this dynamic based on VcpuExit reason.
		Ok(StopReason::Signal(5))
	}

	fn query_supported_features(&self) -> Vec<String> {
		vec!["qXfer:features:read+".to_string()]
	}

	fn query_supported_vcont(&self) -> Result<Cow<'static, [VContFeature]>, Error> {
		Ok(Cow::Borrowed(&[
			VContFeature::Continue,
			VContFeature::ContinueWithSignal,
			VContFeature::Step,
			VContFeature::StepWithSignal,
			//VContFeature::RangeStep,
		]))
	}

	/// TODO: actually implement thread switching for multithread support
	fn set_current_thread(&self, id: ThreadId) -> Result<(), Error> {
		info!("Setting current thread to {:?}", id);
		Ok(())
	}

	/// Return the identifier of the current thread.
	fn current_thread(&self) -> Result<Option<ThreadId>, Error> {
		Ok(Some(ThreadId {
			pid: Id::Id(1),
			tid: Id::Id(1),
		}))
	}

	fn read_general_registers(&self) -> Result<Vec<u8>, Error> {
		let out = Registers::from_kvm(self.current_cpu.borrow().get_vcpu()).encode();
		Ok(out)
	}

	fn write_general_registers(&self, contents: &[u8]) -> Result<(), Error> {
		let regs = Registers::decode(contents);
		regs.to_kvm(self.current_cpu.borrow_mut().get_vcpu_mut());
		Ok(())
	}

	fn read_memory(&self, mem: MemoryRegion) -> Result<Vec<u8>, Error> {
		Ok(unsafe {
			self.current_cpu
				.borrow()
				.read_mem(mem.address as _, mem.length as _)
		}
		.to_vec())
	}

	fn write_memory(&self, address: u64, bytes: &[u8]) -> Result<(), Error> {
		unsafe { self.current_cpu.borrow().write_mem(address as _, bytes) }
		Ok(())
	}

	fn insert_software_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		// bail if breakpoint already exists
		if self
			.state
			.borrow()
			.breakpoints
			.contains_key(&(bp.addr as _))
		{
			return Err(Error::Error(6));
		}

		// save original instruction byte
		let insn = unsafe { self.current_cpu.borrow().read_mem(bp.addr as _, 1) }[0];
		// overwrite with int3
		unsafe { self.current_cpu.borrow().write_mem(bp.addr as _, INT3) }

		let bp = SWBreakpoint { bp, insn };
		self.state
			.borrow_mut()
			.breakpoints
			.insert(bp.bp.addr as _, bp);
		info!("Add breakpoints: {:?}", self.state.borrow().breakpoints);
		Ok(())
	}

	fn remove_software_breakpoint(&self, breakpoint: Breakpoint) -> Result<(), Error> {
		info!("Remove breakpoints: {:?}", self.state.borrow().breakpoints);
		if let Some(bp) = self
			.state
			.borrow_mut()
			.breakpoints
			.remove(&(breakpoint.addr as _))
		{
			// restore original instruction byte
			unsafe {
				self.current_cpu
					.borrow()
					.write_mem(breakpoint.addr as _, &[bp.insn])
			};
			Ok(())
		} else {
			Err(Error::Error(4))
		}
	}

	fn insert_hardware_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::Breakpoint,
			addr: bp.addr as _,
			n_bytes: 1,
		})
	}

	fn remove_hardware_breakpoint(&self, bp: Breakpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::Breakpoint,
			addr: bp.addr as _,
			n_bytes: 1,
		})
	}

	/// Insert a write watchpoint.
	fn insert_write_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchWrite,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Insert a read watchpoint.
	fn insert_read_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Insert an access watchpoint.
	fn insert_access_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.register_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove a write watchpoint.
	fn remove_write_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchWrite,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove a read watchpoint.
	fn remove_read_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// Remove an access watchpoint.
	fn remove_access_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
		self.deregister_hardware_trap(HWBreakpoint {
			kind: BreakpointKind::WatchAccess,
			addr: watchpoint.addr as _,
			n_bytes: watchpoint.n_bytes,
		})
	}

	/// TODO: currently ignores tid/pid, and just continues/steps currently running cpu according to first command
	/// At most apply one action per thread. GDB likes to send default action for other threads,
	/// even if it knows only about 1: "vCont;s:1;c" (step thread 1, continue others)
	fn vcont(&self, actions: Vec<(VCont, Option<ThreadId>)>) -> Result<StopReason, Error> {
		if !actions.is_empty() {
			let (cmd, id) = &actions[0];

			let _id = id.unwrap_or(ThreadId {
				pid: Id::All,
				tid: Id::All,
			});
			//debug!("{:?}", id);
			//println!(self.tracee.pid());
			/*match (id.pid, id.tid) {
				(Id::Id(pid), _) if pid != self.tracee.pid() => continue,
				(_, Id::Id(tid)) if tid != self.tracee.pid() => continue,
				(_, _) => (),
			}*/
			debug!("vcont: {:?}", *cmd);
			// need to clone, since std::ops::Range<T: Copy> should probably also be Copy, but it isn't.
			self.continue_execution(cmd.clone());
		}

		// this reason should not matter, since we dont send it when continuing.
		Ok(StopReason::Signal(0))
	}

	/// TODO: return actual number of threads, not just one
	fn thread_list(&self, reset: bool) -> Result<Vec<ThreadId>, Error> {
		if reset {
			Ok(vec![
				ThreadId {
					pid: Id::Id(1),
					tid: Id::Id(1),
				},
				/*ThreadId{pid: Id::Id(1), tid: Id::Id(2)},
				ThreadId{pid: Id::Id(1), tid: Id::Id(3)},
				ThreadId{pid: Id::Id(1), tid: Id::Id(4)},*/
			])
		} else {
			Ok(Vec::new())
		}
	}

	fn process_list(&self, reset: bool) -> Result<Vec<ProcessInfo>, Error> {
		if reset {
			Ok(vec![ProcessInfo {
				pid: Id::Id(1),
				name: "hermitcore app".to_string(),
				triple: "riscv64gc-unknown-hermit".to_string(),
			}])
		} else {
			Ok(Vec::new())
		}
	}

	// fn read_feature(&self, name: String, offset: u64, length: u64) -> Result<FileData, Error> {
	// 	let targetxml = include_str!("i386-64bit.xml");
	// 	match name.as_ref() {
	// 		"target.xml" => Ok(FileData(
	// 			get_max_subslice(targetxml, offset as _, length as _).to_string(),
	// 		)),
	// 		_ => {
	// 			info!(
	// 				"Error: emote tried to read {}, which is unimplemented",
	// 				name
	// 			);
	// 			Err(Error::Unimplemented)
	// 		}
	// 	}
	// }

	fn host_info(&self) -> Result<String, Error> {
		Ok(format!("triple:{};", b"riscv64gc-unknown-hermit".to_hex()))
	}
}

#[derive(Default, Debug)]
pub struct Registers {
	// Gotten from gnu-binutils/gdb/riscv-tdep.c
	pub zero: Option<u64>,
	pub ra: Option<u64>,
	pub sp: Option<u64>,
	pub gp: Option<u64>,
	pub tp: Option<u64>,
	pub t0: Option<u64>,
	pub t1: Option<u64>,
	pub t2: Option<u64>,
	pub s0: Option<u64>,
	pub s1: Option<u64>,
	pub a0: Option<u64>,
	pub a1: Option<u64>,
	pub a2: Option<u64>,
	pub a3: Option<u64>,
	pub a4: Option<u64>,
	pub a5: Option<u64>,
	pub a6: Option<u64>,
	pub a7: Option<u64>,
	pub s2: Option<u64>,
	pub s3: Option<u64>,
	pub s4: Option<u64>,
	pub s5: Option<u64>,
	pub s6: Option<u64>,
	pub s7: Option<u64>,
	pub s8: Option<u64>,
	pub s9: Option<u64>,
	pub s10: Option<u64>,
	pub s11: Option<u64>,
	pub t3: Option<u64>,
	pub t4: Option<u64>,
	pub t5: Option<u64>,
	pub t6: Option<u64>,
	pub pc: Option<u64>,
}

impl Registers {
	/// Loads the register set from kvm into the register struct
	pub fn from_kvm(cpu: &VcpuFd) -> Self {
		let mut registers = Registers::default();
		registers.zero = Some(0);
		registers.ra = cpu.get_one_reg(KVM_REG_RISCV_CORE_RA).ok();
		registers.sp = cpu.get_one_reg(KVM_REG_RISCV_CORE_SP).ok();
		registers.gp = cpu.get_one_reg(KVM_REG_RISCV_CORE_GP).ok();
		registers.tp = cpu.get_one_reg(KVM_REG_RISCV_CORE_TP).ok();
		registers.t0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T0).ok();
		registers.t1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T1).ok();
		registers.t2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T2).ok();
		registers.s0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S0).ok();
		registers.s1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S1).ok();
		registers.a0 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A0).ok();
		registers.a1 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A1).ok();
		registers.a2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A2).ok();
		registers.a3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A3).ok();
		registers.a4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A4).ok();
		registers.a5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A5).ok();
		registers.a6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A6).ok();
		registers.a7 = cpu.get_one_reg(KVM_REG_RISCV_CORE_A7).ok();
		registers.s2 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S2).ok();
		registers.s3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S3).ok();
		registers.s4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S4).ok();
		registers.s5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S5).ok();
		registers.s6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S6).ok();
		registers.s7 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S7).ok();
		registers.s8 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S8).ok();
		registers.s9 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S9).ok();
		registers.s10 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S10).ok();
		registers.s11 = cpu.get_one_reg(KVM_REG_RISCV_CORE_S11).ok();
		registers.t3 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T3).ok();
		registers.t4 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T4).ok();
		registers.t5 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T5).ok();
		registers.t6 = cpu.get_one_reg(KVM_REG_RISCV_CORE_T6).ok();
		registers.pc = cpu.get_one_reg(KVM_REG_RISCV_CORE_PC).ok();

		registers
	}

	/// Saves a register struct (only where non-None values are) into kvm.
	pub fn to_kvm(&self, cpu: &mut VcpuFd) {
		// let mut regs = cpu.get_regs().expect("Cant get regs from kvm!");
		// let mut sregs = cpu.get_sregs().expect("Cant get sregs from kvm!");

		// regs.r15 = self.r15.unwrap_or(regs.r15);
		// regs.r14 = self.r14.unwrap_or(regs.r14);
		// regs.r13 = self.r13.unwrap_or(regs.r13);
		// regs.r12 = self.r12.unwrap_or(regs.r12);
		// regs.r11 = self.r11.unwrap_or(regs.r11);
		// regs.r10 = self.r10.unwrap_or(regs.r10);
		// regs.r9 = self.r9.unwrap_or(regs.r9);
		// regs.r8 = self.r8.unwrap_or(regs.r8);
		// regs.rax = self.rax.unwrap_or(regs.rax);
		// regs.rbx = self.rbx.unwrap_or(regs.rbx);
		// regs.rcx = self.rcx.unwrap_or(regs.rcx);
		// regs.rdx = self.rdx.unwrap_or(regs.rdx);
		// regs.rsi = self.rsi.unwrap_or(regs.rsi);
		// regs.rdi = self.rdi.unwrap_or(regs.rdi);
		// regs.rsp = self.rsp.unwrap_or(regs.rsp);
		// regs.rbp = self.rbp.unwrap_or(regs.rbp);
		// regs.rip = self.rip.unwrap_or(regs.rip);
		// regs.rflags = self.eflags.unwrap_or(regs.rflags as _) as _;
		// sregs.cs.base = self.cs.unwrap_or(sregs.cs.base as _) as _;
		// sregs.ss.base = self.ss.unwrap_or(sregs.ss.base as _) as _;
		// sregs.ds.base = self.ds.unwrap_or(sregs.ds.base as _) as _;
		// sregs.es.base = self.es.unwrap_or(sregs.es.base as _) as _;
		// sregs.fs.base = self.fs.unwrap_or(sregs.fs.base as _) as _;
		// sregs.gs.base = self.gs.unwrap_or(sregs.gs.base as _) as _;

		//cpu.set_regs(&regs).expect("Cant set regs to kvm!");
	}

	/// take the serialized register set send by gdb and decodes it into a register structure.
	/// uses little endian, order as specified by gdb arch i386:x86-64
	pub fn decode(raw: &[u8]) -> Self {
		let mut registers = Registers::default();
		// let mut raw = raw.clone();

		// registers.rax = raw.read_u64::<LittleEndian>().ok();
		// registers.rbx = raw.read_u64::<LittleEndian>().ok();
		// registers.rcx = raw.read_u64::<LittleEndian>().ok();
		// registers.rdx = raw.read_u64::<LittleEndian>().ok();
		// registers.rsi = raw.read_u64::<LittleEndian>().ok();
		// registers.rdi = raw.read_u64::<LittleEndian>().ok();
		// registers.rbp = raw.read_u64::<LittleEndian>().ok();
		// registers.rsp = raw.read_u64::<LittleEndian>().ok();
		// registers.r8 = raw.read_u64::<LittleEndian>().ok();
		// registers.r9 = raw.read_u64::<LittleEndian>().ok();
		// registers.r10 = raw.read_u64::<LittleEndian>().ok();
		// registers.r11 = raw.read_u64::<LittleEndian>().ok();
		// registers.r12 = raw.read_u64::<LittleEndian>().ok();
		// registers.r13 = raw.read_u64::<LittleEndian>().ok();
		// registers.r14 = raw.read_u64::<LittleEndian>().ok();
		// registers.r15 = raw.read_u64::<LittleEndian>().ok();
		// registers.rip = raw.read_u64::<LittleEndian>().ok();

		// registers.eflags = raw.read_u32::<LittleEndian>().ok();
		// registers.cs = raw.read_u32::<LittleEndian>().ok();
		// registers.ss = raw.read_u32::<LittleEndian>().ok();
		// registers.ds = raw.read_u32::<LittleEndian>().ok();
		// registers.es = raw.read_u32::<LittleEndian>().ok();
		// registers.fs = raw.read_u32::<LittleEndian>().ok();
		// registers.gs = raw.read_u32::<LittleEndian>().ok();

		registers
	}

	/// take the register set and encode it as a u8-vector by concatenating the values
	/// uses little endian, order as specified by gdb arch i386:x86-64
	pub fn encode(&self) -> Vec<u8> {
		let mut out: Vec<u8> = vec![];

		// out.write_u64::<LittleEndian>(self.rax.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rbx.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rcx.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rdx.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rsi.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rdi.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rbp.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rsp.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r8.unwrap_or(0)).unwrap();
		// out.write_u64::<LittleEndian>(self.r9.unwrap_or(0)).unwrap();
		// out.write_u64::<LittleEndian>(self.r10.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r11.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r12.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r13.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r14.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.r15.unwrap_or(0))
		// 	.unwrap();
		// out.write_u64::<LittleEndian>(self.rip.unwrap_or(0))
		// 	.unwrap();

		// out.write_u32::<LittleEndian>(self.eflags.unwrap_or(0))
		// 	.unwrap();
		// out.write_u32::<LittleEndian>(self.cs.unwrap_or(0)).unwrap();
		// out.write_u32::<LittleEndian>(self.ss.unwrap_or(0)).unwrap();
		// out.write_u32::<LittleEndian>(self.ds.unwrap_or(0)).unwrap();
		// out.write_u32::<LittleEndian>(self.es.unwrap_or(0)).unwrap();
		// out.write_u32::<LittleEndian>(self.fs.unwrap_or(0)).unwrap();
		// out.write_u32::<LittleEndian>(self.gs.unwrap_or(0)).unwrap();

		out
	}
}
