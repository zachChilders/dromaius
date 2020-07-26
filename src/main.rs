use eyre::{eyre, Result};
use std::collections::BTreeMap;

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
        Self {
            memory: vec![0; size],
            permissions: vec![Perm(0); size],
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            curr_alc: VirtAddr(0x10000),
            active_alcs: BTreeMap::new(),
        }
    }

    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        let align_size = (size + 0x01f) & !0x0f;

        let base = self.curr_alc;

        // Allocation of 0 should nullop
        if size == 0 {
            return Some(base);
        }

        // Check if we're already out of memory
        if base.0 > self.memory.len() {
            return None;
        }

        // Update current allocation if possible
        self.curr_alc = VirtAddr(self.curr_alc.0.checked_add(align_size)?);

        // Check if updated allocation is out of memory
        if self.curr_alc.0 > self.memory.len() {
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

    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, mut perm: Perm) -> Option<()> {
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

fn main() {
    println!("Hello, world!");
}
