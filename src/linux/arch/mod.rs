#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "riscv64")]
pub mod riscv;

#[cfg(target_arch = "x86_64")]
pub use {
    self::x86::uhyve_init,
    self::x86::vcpu,
    self::x86::gdb
};

#[cfg(target_arch = "riscv64")]
pub use {
    self::riscv::uhyve_init,
    self::riscv::vcpu,
    self::riscv::gdb
};