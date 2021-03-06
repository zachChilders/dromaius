use eyre::{eyre, Result};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    io::Seek,
    path::PathBuf,
};

use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

use goblin::{elf::Elf, error, Object};

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the small, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
pub const DIRTY_BLOCK_SIZE: usize = 1024;

/// If `true` the logic for uninitialized memory tracking will be disabled and
/// all memory will be marked as readable if it has the RAW bit set
const DISABLE_UNINIT: bool = true;

// Don't change these, they're hardcoded in the JIT (namely write vs raw dist,
// during raw bit updates in writes)
pub const PERM_READ: u8 = 1 << 0;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_EXEC: u8 = 1 << 2;
pub const PERM_RAW: u8 = 1 << 3;

/// A permissions byte which corresponds to a memory byte and defines the
/// permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Perm(pub u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub usize);

impl From<u64> for VirtAddr {
    fn from(address: u64) -> Self {
        VirtAddr(address as usize)
    }
}

struct Mmu {
    memory: Vec<u8>,
    permissions: Vec<Perm>,
    dirty: Vec<usize>,
    dirty_bitmap: Vec<u64>,
    curr_alc: VirtAddr,
    active_alcs: BTreeMap<VirtAddr, usize>,
}

impl Mmu {
    /// Create a new memory space which can hold `size` bytes
    pub fn new(size: usize) -> Self {
        let base_mem = 0x10000;
        Self {
            memory: vec![0; size + base_mem],
            permissions: vec![Perm(0); size],
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            curr_alc: VirtAddr(base_mem),
            active_alcs: BTreeMap::new(),
        }
    }

    /// Allocates a memory block `size` long at `offset`.  If no `offset` is given, uses
    /// `curr_alc` instead.
    pub fn allocate(&mut self, size: usize, offset: Option<VirtAddr>) -> Option<VirtAddr> {
        let align_size = (size + 0x01f) & !0x0f;

        let base = offset.unwrap_or(self.curr_alc);

        // Allocation of 0 should nullop
        if size == 0 {
            return Some(base);
        }

        // Check if we're already out of memory
        if base.0 >= self.memory.len() {
            println!("{}, {}", base.0, self.memory.len());
            println!("Broken allocation");
            return None;
        }

        // Update current allocation if possible
        self.curr_alc = VirtAddr(self.curr_alc.0.checked_add(align_size)?);

        // Check if updated allocation is out of memory
        if self.curr_alc.0 > self.memory.len() {
            println!("OOM");
            return None;
        }

        // Update permissions on allocations
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        // If we're still good, insert this as an active allocation
        self.active_alcs.insert(base, size);

        Some(base)
    }

    // Dirty free memory
    pub fn free(&mut self, base: VirtAddr) -> Result<(), VmExit> {
        if let Some(size) = self.active_alcs.remove(&base) {
            self.set_permissions(base, size, Perm(0));
            Ok(())
        } else {
            Err(VmExit::InvalidFree(base))
        }
    }

    pub fn write(&mut self, base: VirtAddr, data: &[u8]) -> Result<(), VmExit> {
        for (offset, datum) in data.iter().enumerate() {
            self.active_alcs
                .insert(VirtAddr(base.0 + offset), *datum as usize);
        }

        Ok(())
    }

    fn set_permissions(&mut self, addr: VirtAddr, size: usize, mut perm: Perm) -> Option<()> {
        if DISABLE_UNINIT {
            if perm.0 & PERM_RAW != 0 {
                perm.0 |= PERM_READ;
            }
        }

        // Set permissions for every byte in the given range
        self.permissions
            .get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = perm);

        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end = (addr.0 + size) / DIRTY_BLOCK_SIZE;

        for block in block_start..=block_end {
            let idx = block / 64;
            let bit = block % 64;

            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                self.dirty.push(block);

                self.dirty_bitmap[idx] |= 1 << bit;
            }
        }

        Some(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Reasons why the VM exited
pub enum VmExit {
    /// The VM exited due to a syscall instruction
    Syscall,

    /// The VM exited cleanly as requested by the VM
    Exit,

    /// A RISC-V software breakpoint instruction was hit
    Ebreak,

    /// The instruction count limit was hit and a timeout has occurred
    Timeout,

    /// An invalid opcode was lifted
    InvalidOpcode,

    /// A free of an invalid region was performed
    InvalidFree(VirtAddr),

    /// An integer overflow occured during a syscall due to bad supplied
    /// arguments by the program
    SyscallIntegerOverflow,

    /// A read or write memory request overflowed the address size
    AddressIntegerOverflow,

    /// The address requested was not in bounds of the guest memory space
    AddressMiss(VirtAddr, usize),

    /// An read of `VirtAddr` failed due to missing permissions
    ReadFault(VirtAddr),

    /// An execution of a `VirtAddr` failed
    ExecFault(VirtAddr),

    /// A read of memory which is uninitialized, but otherwise readable failed
    /// at `VirtAddr`
    UninitFault(VirtAddr),

    /// An write of `VirtAddr` failed due to missing permissions
    WriteFault(VirtAddr),
}

fn load_elf(elf: &Elf, mmu: &mut Mmu, bin: &Vec<u8>) -> Result<()> {

    // Read headers
    let headers = &elf.program_headers;

    // Load the loadable segments from binary
    for header in headers {
        if header.p_type == 1 {
            let alloc = mmu
                .allocate(header.p_memsz as usize, Some(header.p_vaddr.into()))
                .ok_or(eyre!("Couldn't allocate correctly"))?;

            // Copy data into memory
            let low = header.p_offset as usize;
            let high = (header.p_offset + header.p_filesz) as usize;
            let loadable = &bin[low..high];
            mmu.write(alloc, loadable);
        }
    }

    // Jump to entrypoint
    let _entrypoint = elf.header.e_entry;
    println!("Elf loaded successfully!  Fuck ya");

    Ok(())
}

fn main() -> Result<()> {
    let mut mmu = Mmu::new(1024 * 1024 * 4);

    let alloc1 = mmu.allocate(1, None).unwrap();
    let alloc2 = mmu.allocate(1024, None).unwrap();
    let alloc3 = mmu.allocate(2048, None).unwrap();

    println!("Base address of alloc1: {:?}", alloc1);
    println!("Base address of alloc2: {:?}", alloc2);
    println!("Base address of alloc3: {:?}", alloc3);

    mmu.free(alloc3).expect("Dealloc3 failed");
    mmu.free(alloc1).expect("Dealloc1 failed");
    mmu.free(alloc2).expect("Dealloc2 failed");

    println!("Curr address: {:?}", mmu.curr_alc);

    println!("Now lets load an ELF...");
    let path = PathBuf::from("ls");
    let f = fs::read(&path)?;
    match Object::parse(&f)? {
        Object::Elf(elf) => {
            load_elf(&elf, &mut mmu, &f)?;
        }
        _ => println!("unknown"),
    };

    Ok(())
}
