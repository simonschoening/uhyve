/// Arch x86

pub mod vcpu;
pub mod gdb;

use log::debug;
use crate::error::*;
use kvm_ioctls::VmFd;
use kvm_bindings::*;
use vmm_sys_util::eventfd::EventFd;
use crate::consts::*;
use crate::linux::uhyve::{UhyveNetwork, MmapMemory};
use crate::vm::Parameter;
use crate::linux::MemoryRegion;


pub fn uhyve_init(vm: &VmFd, specs: &Parameter, mem: &MmapMemory) -> Result<Option<UhyveNetwork>>{
	debug!("X86 uhyve_init");

	debug!("Initialize interrupt controller");

	// create basic interrupt controller
	vm.create_irq_chip().or_else(to_error)?;

	// enable x2APIC support
	let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
		cap: KVM_CAP_X2APIC_API,
		flags: 0,
		..Default::default()
	};
	cap.args[0] =
		(KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK).into();
	vm.enable_cap(&cap)
		.expect("Unable to enable x2apic support");

	// currently, we support only system, which provides the
	// cpu feature TSC_DEADLINE
	let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
		cap: KVM_CAP_TSC_DEADLINE_TIMER,
		..Default::default()
	};
	cap.args[0] = 0;
	if vm.enable_cap(&cap).is_ok() {
		panic!("Processor feature \"tsc deadline\" isn't supported!")
	}

	let cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
		cap: KVM_CAP_IRQFD,
		..Default::default()
	};
	if vm.enable_cap(&cap).is_ok() {
		panic!("The support of KVM_CAP_IRQFD is curently required");
	}

	let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
		cap: KVM_CAP_X86_DISABLE_EXITS,
		flags: 0,
		..Default::default()
	};
	cap.args[0] =
		(KVM_X86_DISABLE_EXITS_PAUSE | KVM_X86_DISABLE_EXITS_MWAIT | KVM_X86_DISABLE_EXITS_HLT)
			.into();
	vm.enable_cap(&cap)
		.expect("Unable to disable exists due pause instructions");

	let evtfd = EventFd::new(0).unwrap();
	vm.register_irqfd(&evtfd, UHYVE_IRQ_NET).or_else(to_error)?;
	// create TUN/TAP device
	let uhyve_device = match &specs.nic {
		Some(nic) => {
			debug!("Intialize network interface");
			Some(UhyveNetwork::new(
				evtfd,
				nic.to_owned().to_string(),
				mem.host_address() + SHAREDQUEUE_START,
			))
		}
		_ => None,
	};

	Ok(uhyve_device)
}