---
layout: page

title: Reverse

category: infosec
see_my_category_in_header: true

permalink: /infosec/reverse.html

published: true
---

<article class="markdown-body" markdown="1">

***Table of Contents***

* TOC
{:toc}

<br>
*Thanks a lot to [@__paulch](https://twitter.com/__paulch) for directing me on my first binary steps.*

---

# Awesome awesomeness

* [michalmalik/linux-re-101](https://github.com/michalmalik/linux-re-101) - a collection of resources for linux reverse engineering 
* [Reverse Engineering (RE) Tools](https://securedorg.github.io/RE101/section3/)
* [Reverse Engineering Resources](https://pewpewthespells.com/re.html) - ([web.archive.org](http://web.archive.org/web/20161007013208/http://pewpewthespells.com/re.html))

# Reverse Bookmarks

## Helpfull Resources

* [libcdb.com](http://libcdb.com/) - libc database

* [NTAPI undocumented functions](http://undocumented.ntinternals.net/)
* [gcc inline assembly](http://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html)

* [reverse shell cheat sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

## Studying

* [Linux (x86) Exploit Development Series](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
* [Memory Layout of C Programs](http://www.geeksforgeeks.org/memory-layout-of-c-program/)
* [ELF loading and relocs](http://netwinder.osuosl.org/users/p/patb/public_html/elf_relocs.html)
* [Linker and libraries guide](http://docs.oracle.com/cd/E23824_01/html/819-0690/glcdi.html#scrolltoc)
* [Shellcoding for windows and linux tutorial](http://www.vividmachines.com/shellcode/shellcode.html)
* [Linux syscalls (sysenter)](https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/#using-sysenter-system-calls-with-your-own-assembly)

<br>

* [Reverse Engineering Malware 101](https://securedorg.github.io/RE101/)
* The Art of Shellcoding - [Shellcoding 101](https://impureworld.wordpress.com/2017/04/09/the-art-of-shellcoding-shellcoding-101/), [Shellcoding 102](https://impureworld.wordpress.com/2017/04/11/the-art-of-shellcoding-shellcoding-102/), ... (*basics*)

<br>

* opensecuritytraining.info - [exploits1](http://opensecuritytraining.info/Exploits1.html), [exploits2](http://opensecuritytraining.info/Exploits2.html)
* [DefconRussia](https://www.slideshare.net/DefconRussia/)
* [wasm](http://www.wasm.ru/) (link broken look web.archive.org [web.archive wasm](http://web.archive.org/web/20121224160453/http://www.wasm.ru/) ) (forum)

### Heap

* [how2heap](https://github.com/shellphish/how2heap) - tasks on heap exploitation
* [how2heap - resources](https://github.com/shellphish/how2heap#other-resources) - list of awesome resources about heap
* [syscalls used by malloc](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc/) and [understanding-glibc-malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/) and [malloc internals](https://sourceware.org/glibc/wiki/MallocInternals)
* [hook malloc](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html)

<br>

* [Glibc adventures: The Forgotten Chunks](https://www.contextis.com//documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf)
* [Malloc Maleficarium](https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/)
* [Malloc DES-Maleficarium](http://phrack.org/issues/66/10.html)
* [Yet another free() exploitation technique](http://phrack.org/issues/66/6.html)

<br><br>

### Linux kernel

* [grsecurity](https://grsecurity.net/) - still not in linux main line, because they are ... (temper and desire problems)
* [KSPP](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project) - *Kernel Self Protection Project* - [Kees Cook](https://wiki.ubuntu.com/KeesCook) is a leader, looks like they are trying to really implant grsecurity thoughts into linux kernel

<br><br>

### Anti-Reverse

* obfuscation
* [jvoisin/pangu](https://github.com/jvoisin/pangu) - toolset to mess around with gdb

### Remainings

* [getting function names from ***go*** executable in IDA](https://habrahabr.ru/post/325498/)

---

# Practice

## Approaches

### Disassemble

* [IDA + HexRays] - graphic disassembler (most powerfull ourdays)
* [Binary ninja](https://binary.ninja/)
* hopper, binary ninja, etc.

### Fazzing

* [afl - american fuzzy lop](http://lcamtuf.coredump.cx/afl/) - binary fuzzer
* [libFuzzer](http://llvm.org/docs/LibFuzzer.html) - binary fuzzer (llvm bazed)

### Binary Solvers

* [angr](https://docs.angr.io/)
* [KLEE](http://klee.github.io/)
* [Z3Prover/z3](https://github.com/Z3Prover/z3) - Z3 theorem prover

### Shellcodes

* [MSFvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) (metasploit)

* {:.dummy} [Duck toolkit](https://ducktoolkit.com/) - online payload scripts generator (win, linux)
* {:.dummy} [Bunny toolkit](https://bunnytoolkit.com/payloadindex/) - some payload examples

### other

* [Triton](https://triton.quarkslab.com/) - dynamic binary analysis framework
* {:.dummy} [fuzzball](https://github.com/bitblaze-fuzzball/fuzzball) - symbolic execution tool for x86
* {:.dummy} [SASM](https://github.com/Dman95/SASM) - simple opensource crossplatform IDE for NASM, MASM, GAS, FASM assembly languages

* {:.dummy} <div class="spoiler"><div class="spoiler-title"><i>
        Online utils:
    </i></div><div class="spoiler-text" markdown="1">

    * [ODA](https://www.onlinedisassembler.com/odaweb/) - the online disassembler
    * [HexEd.it](https://hexed.it/) - online hexeditor

    </div></div>


<br><br>

---

## Tools

### Basic

* **gdb**

    * [GDB cheat sheet.pdf](http://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)
    * [GDB command reference](http://visualgdb.com/gdbreference/commands/)
    * [debugging with GDB](https://sourceware.org/gdb/onlinedocs/gdb/), ( [debugging with GDB (linux по-русски)](http://rus-linux.net/nlib.php?name=/MyLDP/algol/gdb/otladka-s-gdb.html) )

    gdb assistance:

    * **[gdb peda](https://github.com/longld/peda)** - **Python Exploit Development Assistance for GDB**
    * [pwndbg](https://github.com/zachriggle/pwndbg) ([features](https://github.com/pwndbg/pwndbg/blob/master/FEATURES.md)) - *emulation*, *heap inspection*, ida pro integration, qemu compatibility, etc.

* **[pwntools](https://docs.pwntools.com/en/stable/) - framework and exploit development library ([examples](https://github.com/Gallopsled/pwntools/tree/dev/examples))**

* binutils - basic tools for surface analysis

    `file, readelf, nm, strings, ldd`

* `checksec` - analysis of exploitation countermeasures in binary
* `ltrace, strace` - runtime analysis of system calls

* `ROPgadget, rp++` - search for rop-gadgets, [one_gadget](https://github.com/david942j/one_gadget) - search for one-gadget rce in binary
* hexeditors

    * **[radare2](https://github.com/radare/radare2)** - can view file in many views: hex, assembler, etc. (handy for changing binaries) ([GUI for radare2](https://github.com/hteso/iaito) - in 03.2017 was very bugged, but it progress)
    * hexedit
    * [Hex viewers and editors](https://twitter.com/i/moments/841916822014332930)

### Remainings

#### Format string exploitation

* [libformatstr](https://github.com/hellman/libformatstr) - script to simplify format string exploitation ([usage example](https://blog.techorganic.com/2015/07/01/simplifying-format-string-exploitation-with-libformatstr/))

    [printf format string](https://en.wikipedia.org/wiki/Printf_format_string) (wikipedia printf man)

    basic features: `printf ("%1$s ... %1$s", name)`, `printf (" hifi %n hifi %hn ddd %hhn ddd", &val)`


<br><br>

---

# Theory report

LD_PRELOAD (environment variable) - a list of additional, user-specified, ELF shared objects to be loaded before all others. 

## Assembler

[x86 instruction listing](https://en.wikipedia.org/wiki/X86_instruction_listings#x86_integer_instructions)

### Calling conversions

System V x86_64 calling conversion: `rdi, rsi, rdx, rcx, r8, r9, [stack]`, return values: `rax, rdx` <br>

Syscall conversions:

| arch | bitness | syscall number | arg 1 | arg 2 | arg 3 | arg 4 | arg 5 | arg 6 | call methods | return |
| i386 | 32 | EAX | EBX | ECX | EDX | ESI | EDI | EBP | int 0x80 | EAX |
| x86_64 | 64 | RAX | RDI | RSI | RDX | R10 | R8 | R9 | syscall | RAX |
| ARM eabi | 32 | r7 | r0 | r1 | r2 | r3 | r4 | r5 | swi 0x0 | r1 |

[Other OS calling conversions](https://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions)

<br>

### ROP-gadgets

#### Universal rop-gadget

This rop-gadget for setting `rdi`, `rsi`, `rdx` exist almost in every binary (linux x86_64) (just after `_init_proc`)

``` nasm
.text:00000000004009C0
.text:00000000004009C0     loc_4009C0:                             ; CODE XREF: __libc_csu_init+54j
.text:00000000004009C0 038                 mov     rdx, r13
.text:00000000004009C3 038                 mov     rsi, r14
.text:00000000004009C6 038                 mov     edi, r15d
.text:00000000004009C9 038                 call    qword ptr [r12+rbx*8]
.text:00000000004009CD 038                 add     rbx, 1
.text:00000000004009D1 038                 cmp     rbx, rbp
.text:00000000004009D4 038                 jnz     short loc_4009C0
.text:00000000004009D6
.text:00000000004009D6     loc_4009D6:                             ; CODE XREF: __libc_csu_init+36j
.text:00000000004009D6 038                 add     rsp, 8
.text:00000000004009DA 030                 pop     rbx
.text:00000000004009DB 028                 pop     rbp
.text:00000000004009DC 020                 pop     r12
.text:00000000004009DE 018                 pop     r13
.text:00000000004009E0 010                 pop     r14
.text:00000000004009E2 008                 pop     r15
.text:00000000004009E4 000                 retn
```

#### One-gadget RCE

glibc contains next 3 gadgets, which can be used to start /bin/sh under x86_x64

(if rsi != 0 and points to non-existant memory, there will be problems)

<table>
<colgroup><col style="width: 20%"/><col style="width: 20%"/><col style="width: 20%"/></colgroup>
<td markdown="1">
``` nasm
.text:000000000004526A                 mov     rax, cs:environ_ptr_0
.text:0000000000045271                 lea     rdi, aBinSh     ; "/bin/sh"
.text:0000000000045278                 lea     rsi, [rsp+188h+var_158]
.text:000000000004527D                 mov     cs:dword_3C54A0, 0
.text:0000000000045287                 mov     cs:dword_3C54A4, 0
.text:0000000000045291                 mov     rdx, [rax]
.text:0000000000045294                 call    execve
.text:0000000000045299                 mov     edi, 7Fh        ; status
.text:000000000004529E                 call    _exit
```
</td><td markdown="1">
``` nasm
.text:00000000000EF6C4                 mov     rax, cs:environ_ptr_0
.text:00000000000EF6CB                 lea     rsi, [rsp+1B8h+var_168]
.text:00000000000EF6D0                 lea     rdi, aBinSh     ; "/bin/sh"
.text:00000000000EF6D7                 mov     rdx, [rax]
.text:00000000000EF6DA                 call    execve
.text:00000000000EF6DF                 call    abort
```
</td><td markdown="1">
``` nasm
.text:00000000000F0567                 mov     rax, cs:environ_ptr_0
.text:00000000000F056E                 lea     rsi, [rsp+1D8h+var_168]
.text:00000000000F0573                 lea     rdi, aBinSh     ; "/bin/sh"
.text:00000000000F057A                 mov     rdx, [rax]
.text:00000000000F057D                 call    execve
.text:00000000000F0582                 call    abort
```
</td></table>

More One-gadget RCE's (x32 and x86): [one-gadget RCE in Ubuntu 16.04 libc](https://kimiyuki.net/blog/2016/09/16/one-gadget-rce-ubuntu-1604/)

[one_gadget](https://github.com/david942j/one_gadget) - utility to search one-gadget rce in binaries

<br>

### Malloc hook

Malloc hooks from **.bss** section can rewrited and if they are not null, they will be called.

``` python
from pwn import *
 
libc = ELF('libc.so.6')
print hex(libc.symbols['__free_hook'])
print hex(libc.symbols['__malloc_hook'])
print hex(libc.symbols['__realloc_hook'])
```

Malloc function can be triggered by printing a lot of text by printf (after overload of output buffer, malloc will be triggered)

<br>

### Return to fixup

* [windavid/return_to_fixup](https://github.com/windavid/return_to_fixup) - contains return_to_fixup detailed explanation (*russian text with good conceptual pictures and code snippets*), POCs and payload generators for `link_map`
* [Stepping with GDB during PLT uses and .GOT fixup](http://s.eresi-project.org/inc/articles/elf-runtime-fixup.txt) - explanation of fixup process
* [Dynamic Linking in Linux and Windows, part one](https://www.symantec.com/connect/articles/dynamic-linking-linux-and-windows-part-one) - explanation of fixup process
* [How to hijack the Global Offset Table with pointers for root shells](http://www.infosecwriters.com/text_resources/pdf/GOT_Hijack.pdf)

<br>

***Return to fixup*** - is an exploitation technic allowing to call `_dl_fixup` on `got[some_func]` forcing to load dynamic symbol from other library *(e.g. system from libc)* and write its address into got table as address to `some_func`. `_dl_fixup` tightly works with structure `link_map`, by tampering with it or by replacing it fixup process can be ruled.

***Basic GOT.PLT feature***: `.got` section is filled in runtime (*unless `LD_BIND_NOW=true`*). <br>
After program started, got table does NOT containt pointers to linked functions, but it contains pointers to next instruction in `.plt` section (trampolines). During first function call it is used to find pointer to symbol in dynamic libraries and write it into `.got` section.

*Constrictions*: No PIE, Partial RELRO, eip control, address leak

PLT table structure (example x64):

``` nasm
0x00005555555545b0:  push   QWORD PTR [rip+0x200a52]        # 0x555555755008                                    -- push link_map pointer
0x00005555555545b6:  jmp    QWORD PTR [rip+0x200a54]        # 0x555555755010                                    -- jmp to dl_fixup
0x00005555555545bc:  nop    DWORD PTR [rax+0x0]                                                                 
0x00005555555545c0 <puts@plt+0>:     jmp    QWORD PTR [rip+0x200a52]        # 0x555555755018            -- call function from .got pointer
0x00005555555545c6 <puts@plt+6>:     push   0x0                                                                 -- push reloc_arg       <-- trampoline
0x00005555555545cb <puts@plt+11>:    jmp    0x5555555545b0                                                      -- jmp upward           <-- trampoline
0x00005555555545d0 <__isoc99_sscanf@plt+0>:  jmp    QWORD PTR [rip+0x200a4a]        # 0x555555755020    -- call function from .got pointer
0x00005555555545d6 <__isoc99_sscanf@plt+6>:  push   0x1                                                         -- push reloc_arg       <-- trampoline
0x00005555555545db <__isoc99_sscanf@plt+11>: jmp    0x5555555545b0                                              -- jmp upward           <-- trampoline
```

GOT table structure (example x64):

``` nasm
0x0804A000 _GLOBAL_OFFSET_TABLE_ db 
; first 3 cells are reserved for system pointers
; GOT[0]
; GOT[1] = &link_map
; GOT[2] = trampoline_fixup
0x0804A00C off_804A00C     dd offset getchar          ; GETCHAR = 0 + 3 = 3
0x0804A010 off_804A010     dd offset fgets            ; FGETS = 1 + 3 = 4
```

<div class="spoiler"><div class="spoiler-title" markdown="1">
gdb commands to investigate `link_map`
</div><div class="spoiler-text" markdown="1">

``` gdb
set $GOT = (void**)&_GLOBAL_OFFSET_TABLE_
set $lmap = (struct link_map *)$GOT[1]
p *$lmap

set $DT_STRTAB = 0x5
set $DT_SYMTAB = 0x6
set $DT_JMPREL = 0x17

set $dyn = (Elf64_Rela *)$lmap->l_info[$DT_JMPREL].d_un.d_ptr + $correct_offset1
p *$dyn
set $sym = (Elf64_Sym *)$lmap->l_info[$DT_SYMTAB].d_un.d_ptr + $correct_offset2
p *$sym
set $strtab = (char *)$lmap->l_info[$DT_STRTAB].d_un.d_ptr
x/s $strtab + $sym->st_name
```
</div></div>


<br>

### Shellcodes

* [alpha-numeric shellcodes](http://phrack.org/issues/57/15.html)


<br><br>

---

## General knowledge

#### Heap

Chunck allignment is 16 bytes = 2 qwords (3 lastbits)

Various allocator realizations:

* dlmalloc (Doug Lea)
* ptmalloc (glibc malloc) (pthreads oriented)
* jemalloc (firefox, freebsd) (big chunks allocation oriented)
* tcmalloc (chrome) (caching oriented)
* etc.


<br>

### Binary protections mechanisms

#### OS's mechanisms

* **ASLR** - address space layout randomization - randomize stack, heap, dynamical libraries

*[Ubuntu security features](https://wiki.ubuntu.com/Security/Features)*

#### Compiler's mechanisms

* **Canary** - protection from stack overflow. (Canary is a random value generated by libc at application launch)
* **NX** - no memory regions which is writable and executable simultaneously

    * stack, heap, .bss, .data - `rw-`
    * .rodata - `r--`
    * .code - `rx-`
    * dynamic libraries: PLT(`r-x`) - jumps to address of dynamic library, writen at GOT(`rw-`) by dynamic linker.

* **RELRO** - Relocation Read-Only - after dynamic linker done loading libraries, it marks some regions `r--`, just before applications starts.
    
    * Full RELRO - GOT:`r--`, Partial RELRO - GOT:`rw-`

* **PIE** - position independent executable (aslr can be applied to `.code` `.bss` `.got` section)
* **FORTIFY** - during compilation compiler looks after variables and if it can deduce size of variables passed to libc functions, then compiler will change call on a fortified libc function, which on detection of overflow will terminate program.

More detailed info: [hexcellents](http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/home)


<br>

### Attack related key-words

* ROP - return oriented programming

* Stack/Buffer overflow
* Heap overflow

    * General heap overflow
    * Unlink
    * Use-after-free
    * Double free
    * Malloc-Maleficarium (House of Force, ...)
    * Heap Off-by-one
    * House of Einherjar

* Format string exploitation
* Address leak

<!--## Antiviruses

Antivituse features:

- antiviruses has limit of dearchiving (usually not big).
- antivirus will favourably regard to files with at least one valid signature
- antivirus wil not detect you if there is no harmful actions (like modifying registry, etc.)

    Approaches:

    - modify rights to be able to write into executable region. During execution write there harmful code and execute it.
    - break harmful file into several pieces (exe + dll + dll + ...) so antivirus will not detect them separately

- Obfuscation can be used to defend from static analysis
    
    Examples:
    
    - `jg` and `jle` making 2 contradictory actions one after another-->


<!--=======================================================================================================================-->
<!--=======================================================================================================================-->
<!--=======================================================================================================================-->

<br><br>

---

# Linux kernel analysis

Linux kernel security projects:

* [grsecurity](https://grsecurity.net/features.php)
* [KSPP](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)

## Theory

### Security mechanisms

* ***kaslr*** - kernel address space layout randomization

    kaslr works at system starup therefore single address leakage is enough till system reboot

    Bypass: *address-leak*

    <br>

* ***SMAP*** - supervisor  mode access protection

    The CPU will generate a fault whenever ring0 attempts to *access* code from a page marked with the user bit

    Bypass:

    * kernel primitives
    * ROP-chains

* ***SMEP*** - supervisor mode execution protection - (bit in cr4 register)

    The CPU will generate a fault whenever ring0 attempts to *execute* code from a page marked with the user bit

    Bypass:
    
    * `native_write_cr4` kernel primitive - rewriting cr4 must be accurate because its bits are very important with various meanings
    * ROP-chains


### Attacks

#### Heap

* SLOB/SLAB/SLUB - linux kernel allocator (SLUB - since 2008)

    Linux has *kernel heap*, which is divided into several *cache of allocators* (each allocator contains chuncks of fixed length: 32 bytes, ..., 4K, 8K) (kernel modules can create their own specific allocators) <br>
    Each core has its own set of cache of allocators. <br>
    After chunk is `kfree`-d it will be added to *free list* (in fact - stack) of corresponding allocator. So *last freed chunk will be next to be allocated* - ***use-after-free***, ***use-before-allocate***.

    Defense mechanisms:
    
    * kernel > 4.9 - randomized free list
    * heap-poisoning (write zeros after free)

* ***double-free*** problem:

    page has several `n` allocated chuncks and after freeing all chunks => page will be marked as free <br>
    if the same chunk will be freed `n` times => page will be marked as free => ... some time ... => `bug_on` will trigger and `oops` will happen


## Vulnerability search

Approaches: static analysis, fuzzing, symbolic execution (automatic exploit generation)

* [syzkaller](https://github.com/google/syzkaller) - fuzzer (call system-calls with various parameters)
* [coccinelle](http://coccinelle.lip6.fr/) - static analysis - using specific language description can be created for future checks (Knows semantics of kernel primitives.)
* [gcc plugins](https://gcc.gnu.org/wiki/plugins) (become more popular last time)


<br><br>

## Practice

Example: [vulnerable kernel module example and its exploitation](https://github.com/a13xp0p0v/msuhack)

Linux debugging:

* `qemu -s` + gdb
* **ftrace** - use instrumentation at compilation time, can enable kernel tracing in motion

    `/sys/kernel/debug/tracing/set_ftrace_pid` - trace kernel only when it is related to specified pid process
    `/sys/kernel/debug/tracing/events/kmem/kmalloc/enable` - log usage of kmalloc function

``` bash
# insmod / rmmod

# unhide kernel pointers
echo 0 > /proc/sys/kernel/kptr_restrict

# all kernel functions memory addresses (kaslr)
sudo cat /proc/kallsyms

# info about kernel heap
sudo cat /proc/slabinfo

# info about specific kernel module
ls /sys/module/MODULE_NAME/sections/.text
# e.g. cat /sys/module/MODULE_NAME/sections/.text - module memory address
```

<div class="spoiler"><div class="spoiler-title" markdown="1">
Compile kernel module (linux contains special Makefile for kernel modules compilation)
</div><div class="spoiler-text" markdown="1">

``` make
obj-m := MODULE_EXAMPLE.o

all:
    make -C "/lib/modules/`uname -r`/build" M=${PWD} modules

clean:
    make -C /lib/modules/`uname -r`/build M=${PWD} clean
```
</div></div>

<br>

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### root privilege escalation snippet
</div><div class="spoiler-text" markdown="1">

``` cpp
/* Addresses from System.map (remember KASLR problem) */
#define COMMIT_CREDS_PTR	0xffffffff810a2840lu
#define PREPARE_KERNEL_CRED_PTR	0xffffffff810a2c30lu

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS_PTR;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED_PTR;

void __attribute__((regparm(3))) root_it(unsigned long arg1, bool arg2)
{
	commit_creds(prepare_kernel_cred(0));
}
```

</div></div>



<br><br>

---
---
---

# Tools usage examples (cribs)

``` bash
socat TCP-LISTEN:7777,reuseaddr,fork EXEC:"./binary"

ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only 'pop|ret'

strings -tx /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin"

objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep "__libc_system"

# compile assembler
nasm -f elf ./shellcode.asm && ld -melf_i386 -o shellcode shellcode.o
```

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### gdb
</div><div class="spoiler-text" markdown="1">

``` gdb
r < <(python -c 'print "program input, maybe shellcode"')

run start finish
where up
break watch

info break # see numbers of breakpoints and watchpoints
disable 3 7
enable 3 7
delete 3 7

si # step instruction
ni # step instruction, but steps over 'call'

x/i $pc
x/s $eax
x/10x $sp, $sp+20
# There is a lot of format specifiers for memory output http://visualgdb.com/gdbreference/commands/x

disas $rip, +0x20
print $eax
telescope

set $eax = 0x1234
set {unsigned char}0x400726 = 0x7f

find 0x4005e0, +0x3ac, "wrong code"
find 0x4005e0, +0x3ac, 0x4009c2

info proc map
info file
checksec
context
vmmap
maintenance info sections 

add-symbol-file <my_file.o> <address>
layout split

set $GOT = (void**)&_GLOBAL_OFFSET_TABLE_

# heap analysis
p main_arena
p *(mchunk_ptr) 0x555555756000
```

gdb can patch binaries:

``` bash
$ gdb -write -q ./binary
gdb$ set {unsigned char}0x400726 = 0x7f # Just after starting gdb
gdb$ quit # It is important to quit immidiately
$ # success
```

gdb connect ida:

* `gdbserver localhost:12345 ./binary 3335`
* open with ida same binary
* connect with ida to remote binary

</div></div>

<br>

<!--#### windbg

!ptetree-->

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### pwntools example
</div><div class="spoiler-text" markdown="1">

Not an exploit but just a list of basic commands

``` python
#!/usr/bin/python

from pwn import *

# we can set the context once, instead of writing asm(x, os=..., arch=...) each time
context(os='linux', arch='amd64')

if __name__ == '__main__':

    elf = ELF("./bin")
    mprotect = elf.got['mprotect']
    scanf = elf.plt['__isoc99_scanf']
    lu = next(elf.search('%lu\0'))
    rop1 = next(elf.search(asm("mov rdx, r13; mov rsi, r14; mov edi, r15d")))

    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc.symbols['puts']

    shellcode = asm(shellcraft.amd64.linux.sh())

    r = process('./bin')
    # r = remote('127.0.0.1', 7777)
    r.recvuntil('4: exit\n')
    
    payload = "A" * 16 + "B" * 8
    payload += p64(0x4008F3)  # struct.pack("Q", x)

    r.sendline(shellcode)
    r.interactive()
```

``` python
from pwn import *

fmtstr_payload # helper for format string exploitation
```
</div></div>

<br>

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### radare2
</div><div class="spoiler-text" markdown="1">

``` bash
radare2 -w ./binary
```

Basic commands:

* s main
* V - jump to code
* p - switch to assembler
* c - set cursor
* i - change value

</div></div>

<br>

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### angr
</div><div class="spoiler-text" markdown="1">

Better to install angr into separate python environment, not into system's.

``` python
import angr
project = angr.Project('./fauxware')
init_state = project.factory.full_init_state()
pg = project.factory.path_group(init_state)

pg.step()
# <PathGroup with 1 active>

pg.active
# [<Path with 1 runs (at 0x1020020 : /lib/x86_64-linux-gnu/libc-2.24.so)>]

# ... <83 steps later>

In [82]: pg.step(); pg.active
Out[82]: 
[<Path with 68 runs (at 0x400692 : /home/phoenix/Desktop/angr/test/fauxware)>,
 <Path with 68 runs (at 0x400699 : /home/phoenix/Desktop/angr/test/fauxware)>]


pg.active[0].state.se.any_str(pg.active[0].state.posix.files[0].all_bytes()) # strings stisfying binary constrictions
# '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00'
print repr(path.state.posix.dumps(0))
# '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00'

pg.active[0].state.se.any_n_str(pg.active[0].state.posix.files[0].all_bytes(), 5)
# ['@\x8c \x02\x08@ \x02\x00SOSNEAKY\x80',
#  '\x00\x00\x00\x00\x00\x00\x00\x00\x84SOSNEAKY\x00',
#  '@\x8c \x02\x08@ \x02\x00SOSNEAKY\x04',
#  '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
#  '@\x8c \x02\x08@ \x02\x84SOSNEAKY\x80']

path = pg.active[0]

print path.state.se.constraints
# lots of constraints to be solved for path

path.state.posix.files

# {0: <simuvex.storage.file.SimFile at 0x7fcc44378f90>,
#  1: <simuvex.storage.file.SimFile at 0x7fcc44383090>,
#  2: <simuvex.storage.file.SimFile at 0x7fcc44383150>}
```

``` python
project2 = angr.Project('./fauxware')
init_state2 = project2.factory.full_init_state()
pg2 = project.factory.path_group(init_state2)
pg2.explore(find=0x00000000004006ED) # Start binary solving from arbitrious point

pg2.found
# [<Path with 72 runs (at 0x4006ed : /home/phoenix/Desktop/angr/test/fauxware)>]

path2 = pg2.found[0]
path2.state.se.any_str(path2.state.posix.files[0].all_bytes())
# '\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00'
```

``` python
import angr
project = angr.Project('./amadhj')
init_state = project.factory.full_init_state()

# Start binary from arbitrious point
# PRODUCTIVITY! : LAZY_SOLVES will save a lot of memory and time
pg = project.factory.path_group(project.factory.blank_state(addr=0x40298F, remove_options={simuvex.o.LAZY_SOLVES}))

# Execute traces till finding target address, all traces with avoid address will be dropped
pg.explore(find=0x40288f, avoid=0x4029f1, n=10) # n - max number of steps

# PRODUCTIVITY! : Merge will merge some traces with equivalent conditions and optimize some conditions
# It will save a lot of memory and time!
pg.merge()

path = pg.found[0]
print repr(path.state.se.any_str(path.state.posix.files[0].all_bytes()))

# this is just a shortcut for the above
print repr(path.state.posix.dumps(0))
```

</div></div>

<br>

<div class="spoiler"><div class="spoiler-title" markdown="1">

#### z3
</div><div class="spoiler-text" markdown="1">

``` python
from z3 import *
n = Int('num')

s1 = Solver()
s1.add(n == 201527)
s1.check()
# sat
s1.model()
# [num = 201527]
```

``` python
num1 = BitVec('num1', 32)
num2 = BitVec('num2', 32)

s2 = Solver()
s2.add(URem(num1 * 179 + num2 * 31337, 2**32) == 12345678)
s2.add(URem(num1 * 7877 + num2 * 13, 2**32) == 4105897404)
s2.check()
s2.model()
```

</div></div>

</article>
