# Kernel oops analysis


## Analysis

The kernel oops error message is given below in a screenshot, with details of the error. 
The error in this case is the operation of dereferencing a NULL pointer, which is an exception.

The code below shows the error output
``` 
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
	ESR = 0x96000045
	EC = 0x25: DABT (current EL), IL = 32 bits
	SET = 0, FnV = 0
	EA = 0, S1PTW = 0
	FSC = 0x05: level 1 translation fault
Data abort info:
	ISV = 0, ISS = 0x00000045
	CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=00000000422f6000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 96000045 [#1] SMP
Modules linked in: hello(0) faulty(0) scull(0)
CPU: 0 PID: 158 Comm: sh Tainted: G		0		5.15.18 #1
Hardware name: linux, dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2b0
sp : ffffffc008d23d80
x29: ffffffc008d23d80 x28: ffffff80020e2640 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040001000 x22: 000000000000000c x21: 0000005593ca2a50
x20: 0000005593ca2a50 x19: ffffff800206c100 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008d23df0
x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x40/0xa0
 el0_svc+0x20/0x60
 el0t_64_sync_handler+0xe8/0xf0
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace cdd97ab79af121cc ]---
```

The code dump above shows the error: dereferencing a NULL pointer. Since this is an invalid address to access, the kernel dumps this error. 
Mem abort info: shows the register values (64-bit) that hold details about the error. ESR stands for Exception Syndrome Register, and holds 
the error code for this illegal memory address access.
Data abort info: shows the flags set for this error condition and the pagetable where this error occured. It also shows the CPU core running this 
module, and the PID of the process that caused the fault. In this case,
CPU core running: core 0
modules in error: hello, faulty and scull
PID of process in error: 158

A register dump is provided as well, showing all the ARM general purpose registers.

## Debug

To debug this error, the following resources can be used:
1. PC value: the program counter shows the current execution of code on the CPU, which is the faulty_write error exception handler in this case. This points to where the error occured
2. Another option would be to use objdump, on the "faulty_write" function. This would show the disassembled code of the function, allowing us to check how we arrive at dereferencing a
NULL pointer. 


