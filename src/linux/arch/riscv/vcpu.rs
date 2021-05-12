use crate::consts::*;
use crate::debug_manager::DebugManager;
use crate::error::*;
use crate::linux::virtio::*;
use crate::paging::*;
use crate::vm::{VirtualCPU, BootInfo};
use crate::linux::arch::riscv::consts::*;
use crate::linux::arch::gdb::Registers;
use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd};
use log::{debug, error, info};
use std::sync::{Arc, Mutex};
use std::ptr::write;

const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;

pub struct UhyveCPU {
	id: u32,
	vcpu: VcpuFd,
	vm_start: usize,
	kernel_path: String,
	tx: Option<std::sync::mpsc::SyncSender<usize>>,
	virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	pub dbg: Option<Arc<Mutex<DebugManager>>>,
}

impl UhyveCPU {
	pub fn new(
		id: u32,
		kernel_path: String,
		vcpu: VcpuFd,
		vm_start: usize,
		tx: Option<std::sync::mpsc::SyncSender<usize>>,
		virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
		dbg: Option<Arc<Mutex<DebugManager>>>,
	) -> UhyveCPU {
		UhyveCPU {
			id,
			vcpu,
			vm_start,
			kernel_path,
			tx,
			virtio_device,
			dbg,
		}
	}

	pub fn get_vcpu(&self) -> &VcpuFd {
		&self.vcpu
	}

	pub fn get_vcpu_mut(&mut self) -> &mut VcpuFd {
		&mut self.vcpu
	}
}

impl VirtualCPU for UhyveCPU {
	fn init(&mut self, entry_point: u64, boot_info: *const BootInfo) -> Result<()> {
		// be sure that the multiprocessor is runable
		let mp_state = kvm_mp_state {
			mp_state: KVM_MP_STATE_RUNNABLE,
		};
        self.vcpu.set_one_reg(KVM_REG_RISCV_CORE_PC, entry_point)
            .expect("Failed to set pc register");

		let timebase_freq = self.vcpu.get_one_reg(KVM_REG_RISCV_TIMER_FREQUENCY).expect("Failed to read timebase freq!");
		debug!("detected a timebase frequency of {} Hz", timebase_freq);
		unsafe {write(&mut (*(boot_info as *mut BootInfo)).timebase_freq, timebase_freq)};

		self.vcpu.set_one_reg(KVM_REG_RISCV_CORE_A1, BOOT_INFO_ADDR)
			.expect("Failed to set a1 register");

		self.vcpu.set_mp_state(mp_state).or_else(to_error)?;

		Ok(())
	}

	fn kernel_path(&self) -> String {
		self.kernel_path.clone()
	}

	fn host_address(&self, addr: usize) -> usize {
		addr + self.vm_start
	}

	fn virt_to_phys(&self, addr: usize) -> usize {
		let executable_disable_mask: usize = !PageTableEntryFlags::EXECUTE_DISABLE.bits();
		let mut page_table = self.host_address(BOOT_PML4 as usize) as *const usize;
		let mut page_bits = 39;
		let mut entry: usize = 0;

		for _i in 0..4 {
			let index = (addr >> page_bits) & ((1 << PAGE_MAP_BITS) - 1);
			entry = unsafe { *page_table.add(index) & executable_disable_mask };

			// bit 7 is set if this entry references a 1 GiB (PDPT) or 2 MiB (PDT) page.
			if entry & PageTableEntryFlags::HUGE_PAGE.bits() != 0 {
				return (entry & ((!0usize) << page_bits)) | (addr & !((!0usize) << page_bits));
			} else {
				page_table = self.host_address(entry & !((1 << PAGE_BITS) - 1)) as *const usize;
				page_bits -= PAGE_MAP_BITS;
			}
		}

		(entry & ((!0usize) << PAGE_BITS)) | (addr & !((!0usize) << PAGE_BITS))
	}

	fn run(&mut self) -> Result<Option<i32>> {
		//self.print_registers();

		// // Pause first CPU before first execution, so we have time to attach debugger
		// if self.id == 0 {
		// 	self.gdb_handle_exception(None);
		// }

		let mut pci_addr: u32 = 0;
		let mut pci_addr_set: bool = false;
		loop {
			let exitreason = self.vcpu.run().or_else(to_error)?;
			match exitreason {
				VcpuExit::Hlt => {
					debug!("Halt Exit");
					// currently, we ignore the hlt state
				}
				VcpuExit::Shutdown => {
					self.print_registers();
					debug!("Shutdown Exit");
					break;
				}
				VcpuExit::MmioRead(addr, _) => {
					debug!("KVM: read at 0x{:x}", addr);
					break;
				}
				VcpuExit::MmioWrite(addr, _) => {
					debug!("KVM: write at 0x{:x}", addr);
					self.print_registers();
					break;
				}
				VcpuExit::IoIn(port, addr) => match port {
					PCI_CONFIG_DATA_PORT => {
						if pci_addr & 0x1ff800 == 0 && pci_addr_set {
							let virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.handle_read(pci_addr & 0x3ff, addr);
						} else {
							#[allow(clippy::cast_ptr_alignment)]
							unsafe {
								*(addr.as_ptr() as *mut u32) = 0xffffffff
							};
						}
					}
					PCI_CONFIG_ADDRESS_PORT => {}
					VIRTIO_PCI_STATUS => {
						let virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.read_status(addr);
					}
					VIRTIO_PCI_HOST_FEATURES => {
						let virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.read_host_features(addr);
					}
					VIRTIO_PCI_GUEST_FEATURES => {
						let mut virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.read_requested_features(addr);
					}
					VIRTIO_PCI_CONFIG_OFF_MSIX_OFF..=VIRTIO_PCI_CONFIG_OFF_MSIX_OFF_MAX => {
						let virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.read_mac_byte(addr, port - VIRTIO_PCI_CONFIG_OFF_MSIX_OFF);
					}
					VIRTIO_PCI_ISR => {
						let mut virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.reset_interrupt()
					}
					VIRTIO_PCI_LINK_STATUS_MSIX_OFF => {
						let virtio_device = self.virtio_device.lock().unwrap();
						virtio_device.read_link_status(addr);
					}
					_ => {
						info!("Unhanded IO Exit");
					}
				},
				VcpuExit::IoOut(port, addr) => {
					match port {
						#![allow(clippy::cast_ptr_alignment)]
						SHUTDOWN_PORT => {
							return Ok(None);
						}
						UHYVE_UART_PORT => {
							self.uart(String::from_utf8_lossy(&addr).to_string())?;
						}
						UHYVE_PORT_CMDSIZE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.cmdsize(self.host_address(data_addr))?;
						}
						UHYVE_PORT_CMDVAL => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.cmdval(self.host_address(data_addr))?;
						}
						UHYVE_PORT_NETWRITE => {
							match &self.tx {
								Some(tx_channel) => tx_channel.send(1).unwrap(),

								None => {}
							};
						}
						UHYVE_PORT_EXIT => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							return Ok(Some(self.exit(self.host_address(data_addr))));
						}
						UHYVE_PORT_OPEN => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.open(self.host_address(data_addr))?;
						}
						UHYVE_PORT_WRITE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.write(self.host_address(data_addr))?;
						}
						UHYVE_PORT_READ => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.read(self.host_address(data_addr))?;
						}
						UHYVE_PORT_UNLINK => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.unlink(self.host_address(data_addr))?;
						}
						UHYVE_PORT_LSEEK => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.lseek(self.host_address(data_addr))?;
						}
						UHYVE_PORT_CLOSE => {
							let data_addr: usize =
								unsafe { (*(addr.as_ptr() as *const u32)) as usize };
							self.close(self.host_address(data_addr))?;
						}
						//TODO:
						PCI_CONFIG_DATA_PORT => {
							if pci_addr & 0x1ff800 == 0 && pci_addr_set {
								let mut virtio_device = self.virtio_device.lock().unwrap();
								virtio_device.handle_write(pci_addr & 0x3ff, addr);
							}
						}
						PCI_CONFIG_ADDRESS_PORT => {
							pci_addr = unsafe { *(addr.as_ptr() as *const u32) };
							pci_addr_set = true;
						}
						VIRTIO_PCI_STATUS => {
							let mut virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.write_status(addr);
						}
						VIRTIO_PCI_GUEST_FEATURES => {
							let mut virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.write_requested_features(addr);
						}
						VIRTIO_PCI_QUEUE_NOTIFY => {
							let mut virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.handle_notify_output(addr, self);
						}
						VIRTIO_PCI_QUEUE_SEL => {
							let mut virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.write_selected_queue(addr);
						}
						VIRTIO_PCI_QUEUE_PFN => {
							let mut virtio_device = self.virtio_device.lock().unwrap();
							virtio_device.write_pfn(addr, self);
						}

						_ => {
							panic!("Unhandled IO exit: 0x{:x}", port);
						}
					}
				}
				VcpuExit::Debug => {
					info!("Caught Debug Interrupt! {:?}", exitreason);
					//self.gdb_handle_exception(Some(VcpuExit::Debug));
				}
				VcpuExit::Sbi(sbi_reason) => {
					//info!("SBI {:?}", sbi_reason);
					match sbi_reason.extension_id {
						SBI_CONSOLE_PUTCHAR => {
							self.uart(char::from_u32(sbi_reason.args[0] as u32).unwrap().to_string())
								.expect("UART failed");
						}
						_ => info!("Unhandled SBI call: {:?}", sbi_reason)
					}
					
				}
				VcpuExit::InternalError => {
					error!("Internal error");
					//self.print_registers();

					return Err(Error::UnknownExitReason);
				}
				VcpuExit::SystemEvent(ev_type, ev_flags) => {
					match ev_type{
						KVM_SYSTEM_EVENT_SHUTDOWN => {
							self.print_registers();
							debug!("Shutdown Exit");
							break;
						}
						_ => info!("Unhandled SystemEvent: {:?}", ev_type)
					}
				}
				_ => {
					error!("Unknown exit reason: {:?}", exitreason);
					//self.print_registers();

					return Err(Error::UnknownExitReason);
				}
			}
		}

		Ok(None)
	}

	fn print_registers(&self) {
		//let regs = self.vcpu.get_regs().unwrap();
		let regs = Registers::from_kvm(self.get_vcpu());

		println!();
		println!("Dump state of CPU {}", self.id);
		println!();
		println!("Registers:");
		println!("----------");

		println!("{:?}", regs);
	}
}

impl Drop for UhyveCPU {
	fn drop(&mut self) {
		debug!("Drop vCPU {}", self.id);
		//self.print_registers();
	}
}
