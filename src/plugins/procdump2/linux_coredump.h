/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#ifndef LINUX_PROCDUMP_COREDUMP_H
#define LINUX_PROCDUMP_COREDUMP_H

namespace procdump2_ns
{
//https://llvm.org/doxygen/BinaryFormat_2ELF_8h_source.html

// Segment types.
enum
{
    PT_NULL = 0,            // Unused segment.
    PT_LOAD = 1,            // Loadable segment.
    PT_DYNAMIC = 2,         // Dynamic linking information.
    PT_INTERP = 3,          // Interpreter pathname.
    PT_NOTE = 4,            // Auxiliary information.
    PT_SHLIB = 5,           // Reserved.
    PT_PHDR = 6,            // The program header table itself.
    PT_TLS = 7,             // The thread-local storage template.
    PT_LOOS = 0x60000000,   // Lowest operating system-specific pt entry type.
    PT_HIOS = 0x6fffffff,   // Highest operating system-specific pt entry type.
    PT_LOPROC = 0x70000000, // Lowest processor-specific program hdr entry type.
    PT_HIPROC = 0x7fffffff, // Highest processor-specific program hdr entry type.

    // x86-64 program header types.
    // These all contain stack unwind tables.
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_SUNW_EH_FRAME = 0x6474e550,
    PT_SUNW_UNWIND = 0x6464e550,

    PT_GNU_STACK = 0x6474e551,    // Indicates stack executability.
    PT_GNU_RELRO = 0x6474e552,    // Read-only after relocation.
    PT_GNU_PROPERTY = 0x6474e553, // .note.gnu.property notes sections.

    PT_OPENBSD_MUTABLE = 0x65a3dbe5,   // Like bss, but not immutable.
    PT_OPENBSD_RANDOMIZE = 0x65a3dbe6, // Fill with random data.
    PT_OPENBSD_WXNEEDED = 0x65a3dbe7,  // Program does W^X violations.
    PT_OPENBSD_NOBTCFI = 0x65a3dbe8,   // Do not enforce branch target CFI.
    PT_OPENBSD_BOOTDATA = 0x65a41be6,  // Section for boot arguments.

    // ARM program header types.
    PT_ARM_ARCHEXT = 0x70000000, // Platform architecture compatibility info
    // These all contain stack unwind tables.
    PT_ARM_EXIDX = 0x70000001,
    PT_ARM_UNWIND = 0x70000001,
    // MTE memory tag segment type
    PT_AARCH64_MEMTAG_MTE = 0x70000002,

    // MIPS program header types.
    PT_MIPS_REGINFO = 0x70000000,  // Register usage information.
    PT_MIPS_RTPROC = 0x70000001,   // Runtime procedure table.
    PT_MIPS_OPTIONS = 0x70000002,  // Options segment.
    PT_MIPS_ABIFLAGS = 0x70000003, // Abiflags segment.

    // RISCV program header types.
    PT_RISCV_ATTRIBUTES = 0x70000003,
};

// Segment flags.
enum : unsigned
{
    PF_X = 1,                // Execute
    PF_W = 2,                // Write
    PF_R = 4,                // Read
    PF_MASKOS = 0x0ff00000,  // Bits for operating system-specific semantics.
    PF_MASKPROC = 0xf0000000 // Bits for processor-specific semantics.
};

// Section types.
enum : unsigned
{
    SHT_NULL = 0,           // No associated section (inactive entry).
    SHT_PROGBITS = 1,       // Program-defined contents.
    SHT_SYMTAB = 2,         // Symbol table.
    SHT_STRTAB = 3,         // String table.
    SHT_RELA = 4,           // Relocation entries; explicit addends.
    SHT_HASH = 5,           // Symbol hash table.
    SHT_DYNAMIC = 6,        // Information for dynamic linking.
    SHT_NOTE = 7,           // Information about the file.
    SHT_NOBITS = 8,         // Data occupies no space in the file.
    SHT_REL = 9,            // Relocation entries; no explicit addends.
    SHT_SHLIB = 10,         // Reserved.
    SHT_DYNSYM = 11,        // Symbol table.
    SHT_INIT_ARRAY = 14,    // Pointers to initialization functions.
    SHT_FINI_ARRAY = 15,    // Pointers to termination functions.
    SHT_PREINIT_ARRAY = 16, // Pointers to pre-init functions.
    SHT_GROUP = 17,         // Section group.
    SHT_SYMTAB_SHNDX = 18,  // Indices for SHN_XINDEX entries.
    // Experimental support for SHT_RELR sections. For details, see proposal
    // at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg
    SHT_RELR = 19,         // Relocation entries; only offsets.
    SHT_LOOS = 0x60000000, // Lowest operating system-specific type.
    // Android packed relocation section types.
    // https://android.googlesource.com/platform/bionic/+/6f12bfece5dcc01325e0abba56a46b1bcf991c69/tools/relocation_packer/src/elf_file.cc#37
    SHT_ANDROID_REL = 0x60000001,
    SHT_ANDROID_RELA = 0x60000002,
    SHT_LLVM_ODRTAB = 0x6fff4c00,         // LLVM ODR table.
    SHT_LLVM_LINKER_OPTIONS = 0x6fff4c01, // LLVM Linker Options.
    SHT_LLVM_ADDRSIG = 0x6fff4c03,        // List of address-significant symbols
    // for safe ICF.
    SHT_LLVM_DEPENDENT_LIBRARIES =
        0x6fff4c04,                  // LLVM Dependent Library Specifiers.
    SHT_LLVM_SYMPART = 0x6fff4c05,   // Symbol partition specification.
    SHT_LLVM_PART_EHDR = 0x6fff4c06, // ELF header for loadable partition.
    SHT_LLVM_PART_PHDR = 0x6fff4c07, // Phdrs for loadable partition.
    SHT_LLVM_BB_ADDR_MAP_V0 =
        0x6fff4c08, // LLVM Basic Block Address Map (old version kept for
    // backward-compatibility).
    SHT_LLVM_CALL_GRAPH_PROFILE = 0x6fff4c09, // LLVM Call Graph Profile.
    SHT_LLVM_BB_ADDR_MAP = 0x6fff4c0a,        // LLVM Basic Block Address Map.
    SHT_LLVM_OFFLOADING = 0x6fff4c0b,         // LLVM device offloading data.
    SHT_LLVM_LTO = 0x6fff4c0c,                // .llvm.lto for fat LTO.
    // Android's experimental support for SHT_RELR sections.
    // https://android.googlesource.com/platform/bionic/+/b7feec74547f84559a1467aca02708ff61346d2a/libc/include/elf.h#512
    SHT_ANDROID_RELR = 0x6fffff00,   // Relocation entries; only offsets.
    SHT_GNU_ATTRIBUTES = 0x6ffffff5, // Object attributes.
    SHT_GNU_HASH = 0x6ffffff6,       // GNU-style hash table.
    SHT_GNU_verdef = 0x6ffffffd,     // GNU version definitions.
    SHT_GNU_verneed = 0x6ffffffe,    // GNU version references.
    SHT_GNU_versym = 0x6fffffff,     // GNU symbol versions table.
    SHT_HIOS = 0x6fffffff,           // Highest operating system-specific type.
    SHT_LOPROC = 0x70000000,         // Lowest processor arch-specific type.
    // Fixme: All this is duplicated in MCSectionELF. Why??
    // Exception Index table
    SHT_ARM_EXIDX = 0x70000001U,
    // BPABI DLL dynamic linking pre-emption map
    SHT_ARM_PREEMPTMAP = 0x70000002U,
    //  Object file compatibility attributes
    SHT_ARM_ATTRIBUTES = 0x70000003U,
    SHT_ARM_DEBUGOVERLAY = 0x70000004U,
    SHT_ARM_OVERLAYSECTION = 0x70000005U,
    // Special aarch64-specific sections for MTE support, as described in:
    // https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#7section-types
    SHT_AARCH64_MEMTAG_GLOBALS_STATIC = 0x70000007U,
    SHT_AARCH64_MEMTAG_GLOBALS_DYNAMIC = 0x70000008U,
    SHT_HEX_ORDERED = 0x70000000,   // Link editor is to sort the entries in
    // this section based on their sizes
    SHT_X86_64_UNWIND = 0x70000001, // Unwind information

    SHT_MIPS_REGINFO = 0x70000006,  // Register usage information
    SHT_MIPS_OPTIONS = 0x7000000d,  // General options
    SHT_MIPS_DWARF = 0x7000001e,    // DWARF debugging section.
    SHT_MIPS_ABIFLAGS = 0x7000002a, // ABI information.

    SHT_MSP430_ATTRIBUTES = 0x70000003U,

    SHT_RISCV_ATTRIBUTES = 0x70000003U,

    SHT_CSKY_ATTRIBUTES = 0x70000001U,

    SHT_HIPROC = 0x7fffffff, // Highest processor arch-specific type.
    SHT_LOUSER = 0x80000000, // Lowest type reserved for applications.
    SHT_HIUSER = 0xffffffff  // Highest type reserved for applications.
};

// Section flags.
enum : unsigned
{
    // Section data should be writable during execution.
    SHF_WRITE = 0x1,

    // Section occupies memory during program execution.
    SHF_ALLOC = 0x2,

    // Section contains executable machine instructions.
    SHF_EXECINSTR = 0x4,

    // The data in this section may be merged.
    SHF_MERGE = 0x10,

    // The data in this section is null-terminated strings.
    SHF_STRINGS = 0x20,

    // A field in this section holds a section header table index.
    SHF_INFO_LINK = 0x40U,

    // Adds special ordering requirements for link editors.
    SHF_LINK_ORDER = 0x80U,

    // This section requires special OS-specific processing to avoid incorrect
    // behavior.
    SHF_OS_NONCONFORMING = 0x100U,

    // This section is a member of a section group.
    SHF_GROUP = 0x200U,

    // This section holds Thread-Local Storage.
    SHF_TLS = 0x400U,

    // Identifies a section containing compressed data.
    SHF_COMPRESSED = 0x800U,

    // This section should not be garbage collected by the linker.
    SHF_GNU_RETAIN = 0x200000,

    // This section is excluded from the final executable or shared library.
    SHF_EXCLUDE = 0x80000000U,

    // Start of target-specific flags.

    SHF_MASKOS = 0x0ff00000,

    // Solaris equivalent of SHF_GNU_RETAIN.
    SHF_SUNW_NODISCARD = 0x00100000,

    // Bits indicating processor-specific flags.
    SHF_MASKPROC = 0xf0000000,

    /// All sections with the "d" flag are grouped together by the linker to form
    /// the data section and the dp register is set to the start of the section by
    /// the boot code.
    XCORE_SHF_DP_SECTION = 0x10000000,

    /// All sections with the "c" flag are grouped together by the linker to form
    /// the constant pool and the cp register is set to the start of the constant
    /// pool by the boot code.
    XCORE_SHF_CP_SECTION = 0x20000000,

    // If an object file section does not have this flag set, then it may not hold
    // more than 2GB and can be freely referred to in objects using smaller code
    // models. Otherwise, only objects using larger code models can refer to them.
    // For example, a medium code model object can refer to data in a section that
    // sets this flag besides being able to refer to data in a section that does
    // not set it; likewise, a small code model object can refer only to code in a
    // section that does not set this flag.
    SHF_X86_64_LARGE = 0x10000000,

    // All sections with the GPREL flag are grouped into a global data area
    // for faster accesses
    SHF_HEX_GPREL = 0x10000000,

    // Section contains text/data which may be replicated in other sections.
    // Linker must retain only one copy.
    SHF_MIPS_NODUPES = 0x01000000,

    // Linker must generate implicit hidden weak names.
    SHF_MIPS_NAMES = 0x02000000,

    // Section data local to process.
    SHF_MIPS_LOCAL = 0x04000000,

    // Do not strip this section.
    SHF_MIPS_NOSTRIP = 0x08000000,

    // Section must be part of global data area.
    SHF_MIPS_GPREL = 0x10000000,

    // This section should be merged.
    SHF_MIPS_MERGE = 0x20000000,

    // Address size to be inferred from section entry size.
    SHF_MIPS_ADDR = 0x40000000,

    // Section data is string data by default.
    SHF_MIPS_STRING = 0x80000000,

    // Make code section unreadable when in execute-only mode
    SHF_ARM_PURECODE = 0x20000000
};

// File types.
// See current registered ELF types at:
//    http://www.sco.com/developers/gabi/latest/ch4.eheader.html
enum
{
    ET_NONE = 0,        // No file type
    ET_REL = 1,         // Relocatable file
    ET_EXEC = 2,        // Executable file
    ET_DYN = 3,         // Shared object file
    ET_CORE = 4,        // Core file
    ET_LOOS = 0xfe00,   // Beginning of operating system-specific codes
    ET_HIOS = 0xfeff,   // Operating system-specific
    ET_LOPROC = 0xff00, // Beginning of processor-specific codes
    ET_HIPROC = 0xffff  // Processor-specific
};

// e_ident size and indices.
enum
{
    EI_MAG0 = 0,       // File identification index.
    EI_MAG1 = 1,       // File identification index.
    EI_MAG2 = 2,       // File identification index.
    EI_MAG3 = 3,       // File identification index.
    EI_CLASS = 4,      // File class.
    EI_DATA = 5,       // Data encoding.
    EI_VERSION = 6,    // File version.
    EI_OSABI = 7,      // OS/ABI identification.
    EI_ABIVERSION = 8, // ABI version.
    EI_PAD = 9,        // Start of padding bytes.
    EI_NIDENT = 16     // Number of bytes in e_ident.
};

// Machine architectures
// See current registered ELF machine architectures at:
//    http://www.uxsglobal.com/developers/gabi/latest/ch4.eheader.html
enum
{
    EM_NONE = 0,           // No machine
    EM_M32 = 1,            // AT&T WE 32100
    EM_SPARC = 2,          // SPARC
    EM_386 = 3,            // Intel 386
    EM_68K = 4,            // Motorola 68000
    EM_88K = 5,            // Motorola 88000
    EM_IAMCU = 6,          // Intel MCU
    EM_860 = 7,            // Intel 80860
    EM_MIPS = 8,           // MIPS R3000
    EM_S370 = 9,           // IBM System/370
    EM_MIPS_RS3_LE = 10,   // MIPS RS3000 Little-endian
    EM_PARISC = 15,        // Hewlett-Packard PA-RISC
    EM_VPP500 = 17,        // Fujitsu VPP500
    EM_SPARC32PLUS = 18,   // Enhanced instruction set SPARC
    EM_960 = 19,           // Intel 80960
    EM_PPC = 20,           // PowerPC
    EM_PPC64 = 21,         // PowerPC64
    EM_S390 = 22,          // IBM System/390
    EM_SPU = 23,           // IBM SPU/SPC
    EM_V800 = 36,          // NEC V800
    EM_FR20 = 37,          // Fujitsu FR20
    EM_RH32 = 38,          // TRW RH-32
    EM_RCE = 39,           // Motorola RCE
    EM_ARM = 40,           // ARM
    EM_ALPHA = 41,         // DEC Alpha
    EM_SH = 42,            // Hitachi SH
    EM_SPARCV9 = 43,       // SPARC V9
    EM_TRICORE = 44,       // Siemens TriCore
    EM_ARC = 45,           // Argonaut RISC Core
    EM_H8_300 = 46,        // Hitachi H8/300
    EM_H8_300H = 47,       // Hitachi H8/300H
    EM_H8S = 48,           // Hitachi H8S
    EM_H8_500 = 49,        // Hitachi H8/500
    EM_IA_64 = 50,         // Intel IA-64 processor architecture
    EM_MIPS_X = 51,        // Stanford MIPS-X
    EM_COLDFIRE = 52,      // Motorola ColdFire
    EM_68HC12 = 53,        // Motorola M68HC12
    EM_MMA = 54,           // Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55,           // Siemens PCP
    EM_NCPU = 56,          // Sony nCPU embedded RISC processor
    EM_NDR1 = 57,          // Denso NDR1 microprocessor
    EM_STARCORE = 58,      // Motorola Star*Core processor
    EM_ME16 = 59,          // Toyota ME16 processor
    EM_ST100 = 60,         // STMicroelectronics ST100 processor
    EM_TINYJ = 61,         // Advanced Logic Corp. TinyJ embedded processor family
    EM_X86_64 = 62,        // AMD x86-64 architecture
    EM_PDSP = 63,          // Sony DSP Processor
    EM_PDP10 = 64,         // Digital Equipment Corp. PDP-10
    EM_PDP11 = 65,         // Digital Equipment Corp. PDP-11
    EM_FX66 = 66,          // Siemens FX66 microcontroller
    EM_ST9PLUS = 67,       // STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7 = 68,           // STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16 = 69,        // Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70,        // Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71,        // Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72,        // Motorola MC68HC05 Microcontroller
    EM_SVX = 73,           // Silicon Graphics SVx
    EM_ST19 = 74,          // STMicroelectronics ST19 8-bit microcontroller
    EM_VAX = 75,           // Digital VAX
    EM_CRIS = 76,          // Axis Communications 32-bit embedded processor
    EM_JAVELIN = 77,       // Infineon Technologies 32-bit embedded processor
    EM_FIREPATH = 78,      // Element 14 64-bit DSP Processor
    EM_ZSP = 79,           // LSI Logic 16-bit DSP Processor
    EM_MMIX = 80,          // Donald Knuth's educational 64-bit processor
    EM_HUANY = 81,         // Harvard University machine-independent object files
    EM_PRISM = 82,         // SiTera Prism
    EM_AVR = 83,           // Atmel AVR 8-bit microcontroller
    EM_FR30 = 84,          // Fujitsu FR30
    EM_D10V = 85,          // Mitsubishi D10V
    EM_D30V = 86,          // Mitsubishi D30V
    EM_V850 = 87,          // NEC v850
    EM_M32R = 88,          // Mitsubishi M32R
    EM_MN10300 = 89,       // Matsushita MN10300
    EM_MN10200 = 90,       // Matsushita MN10200
    EM_PJ = 91,            // picoJava
    EM_OPENRISC = 92,      // OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT = 93,   // ARC International ARCompact processor (old
    // spelling/synonym: EM_ARC_A5)
    EM_XTENSA = 94,        // Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95,     // Alphamosaic VideoCore processor
    EM_TMM_GPP = 96,       // Thompson Multimedia General Purpose Processor
    EM_NS32K = 97,         // National Semiconductor 32000 series
    EM_TPC = 98,           // Tenor Network TPC processor
    EM_SNP1K = 99,         // Trebia SNP 1000 processor
    EM_ST200 = 100,        // STMicroelectronics (www.st.com) ST200
    EM_IP2K = 101,         // Ubicom IP2xxx microcontroller family
    EM_MAX = 102,          // MAX Processor
    EM_CR = 103,           // National Semiconductor CompactRISC microprocessor
    EM_F2MC16 = 104,       // Fujitsu F2MC16
    EM_MSP430 = 105,       // Texas Instruments embedded microcontroller msp430
    EM_BLACKFIN = 106,     // Analog Devices Blackfin (DSP) processor
    EM_SE_C33 = 107,       // S1C33 Family of Seiko Epson processors
    EM_SEP = 108,          // Sharp embedded microprocessor
    EM_ARCA = 109,         // Arca RISC Microprocessor
    EM_UNICORE = 110,      // Microprocessor series from PKU-Unity Ltd. and MPRC
    // of Peking University
    EM_EXCESS = 111,       // eXcess: 16/32/64-bit configurable embedded CPU
    EM_DXP = 112,          // Icera Semiconductor Inc. Deep Execution Processor
    EM_ALTERA_NIOS2 = 113, // Altera Nios II soft-core processor
    EM_CRX = 114,          // National Semiconductor CompactRISC CRX
    EM_XGATE = 115,        // Motorola XGATE embedded processor
    EM_C166 = 116,         // Infineon C16x/XC16x processor
    EM_M16C = 117,         // Renesas M16C series microprocessors
    EM_DSPIC30F = 118,     // Microchip Technology dsPIC30F Digital Signal
    // Controller
    EM_CE = 119,           // Freescale Communication Engine RISC core
    EM_M32C = 120,         // Renesas M32C series microprocessors
    EM_TSK3000 = 131,      // Altium TSK3000 core
    EM_RS08 = 132,         // Freescale RS08 embedded processor
    EM_SHARC = 133,        // Analog Devices SHARC family of 32-bit DSP
    // processors
    EM_ECOG2 = 134,        // Cyan Technology eCOG2 microprocessor
    EM_SCORE7 = 135,       // Sunplus S+core7 RISC processor
    EM_DSP24 = 136,        // New Japan Radio (NJR) 24-bit DSP Processor
    EM_VIDEOCORE3 = 137,   // Broadcom VideoCore III processor
    EM_LATTICEMICO32 = 138, // RISC processor for Lattice FPGA architecture
    EM_SE_C17 = 139,        // Seiko Epson C17 family
    EM_TI_C6000 = 140,      // The Texas Instruments TMS320C6000 DSP family
    EM_TI_C2000 = 141,      // The Texas Instruments TMS320C2000 DSP family
    EM_TI_C5500 = 142,      // The Texas Instruments TMS320C55x DSP family
    EM_MMDSP_PLUS = 160,    // STMicroelectronics 64bit VLIW Data Signal Processor
    EM_CYPRESS_M8C = 161,   // Cypress M8C microprocessor
    EM_R32C = 162,          // Renesas R32C series microprocessors
    EM_TRIMEDIA = 163,      // NXP Semiconductors TriMedia architecture family
    EM_HEXAGON = 164,       // Qualcomm Hexagon processor
    EM_8051 = 165,          // Intel 8051 and variants
    EM_STXP7X = 166,        // STMicroelectronics STxP7x family of configurable
    // and extensible RISC processors
    EM_NDS32 = 167,         // Andes Technology compact code size embedded RISC
    // processor family
    EM_ECOG1 = 168,         // Cyan Technology eCOG1X family
    EM_ECOG1X = 168,        // Cyan Technology eCOG1X family
    EM_MAXQ30 = 169,        // Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_XIMO16 = 170,        // New Japan Radio (NJR) 16-bit DSP Processor
    EM_MANIK = 171,         // M2000 Reconfigurable RISC Microprocessor
    EM_CRAYNV2 = 172,       // Cray Inc. NV2 vector architecture
    EM_RX = 173,            // Renesas RX family
    EM_METAG = 174,         // Imagination Technologies META processor
    // architecture
    EM_MCST_ELBRUS = 175,   // MCST Elbrus general purpose hardware architecture
    EM_ECOG16 = 176,        // Cyan Technology eCOG16 family
    EM_CR16 = 177,          // National Semiconductor CompactRISC CR16 16-bit
    // microprocessor
    EM_ETPU = 178,          // Freescale Extended Time Processing Unit
    EM_SLE9X = 179,         // Infineon Technologies SLE9X core
    EM_L10M = 180,          // Intel L10M
    EM_K10M = 181,          // Intel K10M
    EM_AARCH64 = 183,       // ARM AArch64
    EM_AVR32 = 185,         // Atmel Corporation 32-bit microprocessor family
    EM_STM8 = 186,          // STMicroeletronics STM8 8-bit microcontroller
    EM_TILE64 = 187,        // Tilera TILE64 multicore architecture family
    EM_TILEPRO = 188,       // Tilera TILEPro multicore architecture family
    EM_MICROBLAZE = 189,    // Xilinx MicroBlaze 32-bit RISC soft processor core
    EM_CUDA = 190,          // NVIDIA CUDA architecture
    EM_TILEGX = 191,        // Tilera TILE-Gx multicore architecture family
    EM_CLOUDSHIELD = 192,   // CloudShield architecture family
    EM_COREA_1ST = 193,     // KIPO-KAIST Core-A 1st generation processor family
    EM_COREA_2ND = 194,     // KIPO-KAIST Core-A 2nd generation processor family
    EM_ARC_COMPACT2 = 195,  // Synopsys ARCompact V2
    EM_OPEN8 = 196,         // Open8 8-bit RISC soft processor core
    EM_RL78 = 197,          // Renesas RL78 family
    EM_VIDEOCORE5 = 198,    // Broadcom VideoCore V processor
    EM_78KOR = 199,         // Renesas 78KOR family
    EM_56800EX = 200,       // Freescale 56800EX Digital Signal Controller (DSC)
    EM_BA1 = 201,           // Beyond BA1 CPU architecture
    EM_BA2 = 202,           // Beyond BA2 CPU architecture
    EM_XCORE = 203,         // XMOS xCORE processor family
    EM_MCHP_PIC = 204,      // Microchip 8-bit PIC(r) family
    EM_INTEL205 = 205,      // Reserved by Intel
    EM_INTEL206 = 206,      // Reserved by Intel
    EM_INTEL207 = 207,      // Reserved by Intel
    EM_INTEL208 = 208,      // Reserved by Intel
    EM_INTEL209 = 209,      // Reserved by Intel
    EM_KM32 = 210,          // KM211 KM32 32-bit processor
    EM_KMX32 = 211,         // KM211 KMX32 32-bit processor
    EM_KMX16 = 212,         // KM211 KMX16 16-bit processor
    EM_KMX8 = 213,          // KM211 KMX8 8-bit processor
    EM_KVARC = 214,         // KM211 KVARC processor
    EM_CDP = 215,           // Paneve CDP architecture family
    EM_COGE = 216,          // Cognitive Smart Memory Processor
    EM_COOL = 217,          // iCelero CoolEngine
    EM_NORC = 218,          // Nanoradio Optimized RISC
    EM_CSR_KALIMBA = 219,   // CSR Kalimba architecture family
    EM_AMDGPU = 224,        // AMD GPU architecture
    EM_RISCV = 243,         // RISC-V
    EM_LANAI = 244,         // Lanai 32-bit processor
    EM_BPF = 247,           // Linux kernel bpf virtual machine
    EM_VE = 251,            // NEC SX-Aurora VE
    EM_CSKY = 252,          // C-SKY 32-bit processor
    EM_LOONGARCH = 258,     // LoongArch
};

// Versioning
enum
{
    EV_NONE = 0,
    EV_CURRENT = 1
};

// OS ABI identification.
enum
{
    ELFOSABI_NONE = 0,           // UNIX System V ABI
    ELFOSABI_HPUX = 1,           // HP-UX operating system
    ELFOSABI_NETBSD = 2,         // NetBSD
    ELFOSABI_GNU = 3,            // GNU/Linux
    ELFOSABI_LINUX = 3,          // Historical alias for ELFOSABI_GNU.
    ELFOSABI_HURD = 4,           // GNU/Hurd
    ELFOSABI_SOLARIS = 6,        // Solaris
    ELFOSABI_AIX = 7,            // AIX
    ELFOSABI_IRIX = 8,           // IRIX
    ELFOSABI_FREEBSD = 9,        // FreeBSD
    ELFOSABI_TRU64 = 10,         // TRU64 UNIX
    ELFOSABI_MODESTO = 11,       // Novell Modesto
    ELFOSABI_OPENBSD = 12,       // OpenBSD
    ELFOSABI_OPENVMS = 13,       // OpenVMS
    ELFOSABI_NSK = 14,           // Hewlett-Packard Non-Stop Kernel
    ELFOSABI_AROS = 15,          // AROS
    ELFOSABI_FENIXOS = 16,       // FenixOS
    ELFOSABI_CLOUDABI = 17,      // Nuxi CloudABI
    ELFOSABI_FIRST_ARCH = 64,    // First architecture-specific OS ABI
    ELFOSABI_AMDGPU_HSA = 64,    // AMD HSA runtime
    ELFOSABI_AMDGPU_PAL = 65,    // AMD PAL runtime
    ELFOSABI_AMDGPU_MESA3D = 66, // AMD GCN GPUs (GFX6+) for MESA runtime
    ELFOSABI_ARM = 97,           // ARM
    ELFOSABI_C6000_ELFABI = 64,  // Bare-metal TMS320C6000
    ELFOSABI_C6000_LINUX = 65,   // Linux TMS320C6000
    ELFOSABI_STANDALONE = 255,   // Standalone (embedded) application
    ELFOSABI_LAST_ARCH = 255     // Last Architecture-specific OS ABI
};

// Program header for ELF64.
struct elf64_program_header
{
    uint32_t p_type;        // Type of segment
    uint32_t p_flags;       // Segment flags
    uint64_t p_offset;      // File offset where segment is located, in bytes
    uint64_t p_vaddr;       // Virtual address of beginning of segment
    uint64_t p_paddr;       // Physical addr of beginning of segment (OS-specific)
    uint64_t p_filesz;      // Num. of bytes in file image of segment (may be zero)
    uint64_t p_memsz;       // Num. of bytes in mem image of segment (may be zero)
    uint64_t p_align;       // Segment alignment constraint

    elf64_program_header(uint32_t p_type, uint32_t p_flags, uint64_t p_offset, uint64_t p_vaddr, uint64_t p_paddr, uint64_t p_filesz, uint64_t p_memsz)
        : p_type(p_type)
        , p_flags(p_flags)
        , p_offset(p_offset)
        , p_vaddr(p_vaddr)
        , p_paddr(p_paddr)
        , p_filesz(p_filesz)
        , p_memsz(p_memsz)
        , p_align(1)
    {
    }
};

// Section header for ELF64.
struct elf64_section_header
{
    uint32_t sh_name;       // Section name (index into string table)
    uint32_t sh_type;       // Section type (SHT_*)
    uint64_t sh_flags;      // Section flags (SHF_*)
    uint64_t sh_addr;       // Address where section is to be loaded
    uint64_t sh_offset;     // File offset of section data, in bytes
    uint64_t sh_size;       // Size of section, in bytes
    uint32_t sh_link;       // Section type-specific header table index link
    uint32_t sh_info;       // Section type-specific extra information
    uint64_t sh_addralign;  // Section address alignment
    uint64_t sh_entsize;    // Size of records contained within the section

    elf64_section_header(uint32_t sh_name, uint32_t sh_type, uint64_t sh_flags, uint64_t sh_addr, uint64_t sh_offset, uint64_t sh_size, uint64_t sh_addralign)
        : sh_name(sh_name)
        , sh_type(sh_type)
        , sh_flags(sh_flags)
        , sh_addr(sh_addr)
        , sh_offset(sh_offset)
        , sh_size(sh_size)
        , sh_link(0)
        , sh_info(0)
        , sh_addralign(sh_addralign)
        , sh_entsize(0)
    {
    }
};

// 64-bit ELF header.
struct elf64_header
{
    unsigned char e_ident[EI_NIDENT]; // ELF Identification bytes
    uint16_t e_type;                  // Type of file (see ET_* below)
    uint16_t e_machine;     // Required architecture for this file (see EM_*)
    uint32_t e_version;     // Must be equal to 1
    uint64_t e_entry;       // Address to jump to in order to start program
    uint64_t e_phoff;       // Program header table's file offset, in bytes
    uint64_t e_shoff;       // Section header table's file offset, in bytes
    uint32_t e_flags;       // Processor-specific flags
    uint16_t e_ehsize;      // Size of ELF header, in bytes
    uint16_t e_phentsize;   // Size of an entry in the program header table
    uint16_t e_phnum;       // Number of entries in the program header table
    uint16_t e_shentsize;   // Size of an entry in the section header table
    uint16_t e_shnum;       // Number of entries in the section header table
    uint16_t e_shstrndx;    // Sect hdr table index of sect name string table

    elf64_header(uint64_t e_phoff, uint64_t e_shoff, uint16_t e_phnum, uint16_t e_shnum, uint16_t e_shstrndx)
        : e_ident{0x7f, 'E', 'L', 'F', 0x2, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
        , e_type(ET_CORE)
        , e_machine(EM_X86_64)
        , e_version(EV_CURRENT)
        , e_entry(0)
        , e_phoff(e_phoff)
        , e_shoff(e_shoff)
        , e_flags(0)
        , e_ehsize(sizeof(struct elf64_header))
        , e_phentsize(sizeof(struct elf64_program_header))
        , e_phnum(e_phnum)
        , e_shentsize(sizeof(struct elf64_section_header))
        , e_shnum(e_shnum)
        , e_shstrndx(e_shstrndx)
    {
    }
};

enum : unsigned
{
    NT_PRSTATUS = 1,
    NT_FPREGSET = 2,
    NT_PRPSINFO = 3,
    NT_TASKSTRUCT = 4,
    NT_AUXV = 6,
    NT_PSTATUS = 10,
    NT_FPREGS = 12,
    NT_PSINFO = 13,
    NT_LWPSTATUS = 16,
    NT_LWPSINFO = 17,
    NT_WIN32PSTATUS = 18,

    NT_PPC_VMX = 0x100,
    NT_PPC_VSX = 0x102,
    NT_PPC_TAR = 0x103,
    NT_PPC_PPR = 0x104,
    NT_PPC_DSCR = 0x105,
    NT_PPC_EBB = 0x106,
    NT_PPC_PMU = 0x107,
    NT_PPC_TM_CGPR = 0x108,
    NT_PPC_TM_CFPR = 0x109,
    NT_PPC_TM_CVMX = 0x10a,
    NT_PPC_TM_CVSX = 0x10b,
    NT_PPC_TM_SPR = 0x10c,
    NT_PPC_TM_CTAR = 0x10d,
    NT_PPC_TM_CPPR = 0x10e,
    NT_PPC_TM_CDSCR = 0x10f,

    NT_386_TLS = 0x200,
    NT_386_IOPERM = 0x201,
    NT_X86_XSTATE = 0x202,

    NT_S390_HIGH_GPRS = 0x300,
    NT_S390_TIMER = 0x301,
    NT_S390_TODCMP = 0x302,
    NT_S390_TODPREG = 0x303,
    NT_S390_CTRS = 0x304,
    NT_S390_PREFIX = 0x305,
    NT_S390_LAST_BREAK = 0x306,
    NT_S390_SYSTEM_CALL = 0x307,
    NT_S390_TDB = 0x308,
    NT_S390_VXRS_LOW = 0x309,
    NT_S390_VXRS_HIGH = 0x30a,
    NT_S390_GS_CB = 0x30b,
    NT_S390_GS_BC = 0x30c,

    NT_ARM_VFP = 0x400,
    NT_ARM_TLS = 0x401,
    NT_ARM_HW_BREAK = 0x402,
    NT_ARM_HW_WATCH = 0x403,
    NT_ARM_SVE = 0x405,
    NT_ARM_PAC_MASK = 0x406,
    NT_ARM_SSVE = 0x40b,
    NT_ARM_ZA = 0x40c,
    NT_ARM_ZT = 0x40d,

    NT_FILE = 0x46494c45,
    NT_PRXFPREG = 0x46e62b7f,
    NT_SIGINFO = 0x53494749,
};

#define NT_CORE 0x45524f43
#define NT_CORE_SIZE 5

struct __attribute__ ((packed, aligned(4))) elf64_note_header
{
    uint32_t namesz;
    uint32_t size;
    uint32_t type;
    uint64_t name;
    elf64_note_header(uint32_t size)
        : namesz(NT_CORE_SIZE)
        , size(size)
        , type(NT_FILE)
        , name(NT_CORE)
    {
    }
};

struct elf64_nt_file_header
{
    uint64_t count;
    uint64_t page_size;
    elf64_nt_file_header(uint64_t count, uint64_t page_size)
        : count(count)
        , page_size(page_size)
    {
    }
};

//https://www.gabriel.urdhr.fr/2015/05/29/core-file/#file-association

struct elf64_nt_file_entry
{
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    elf64_nt_file_entry(uint64_t start, uint64_t end, uint64_t offset)
        : start(start)
        , end(end)
        , offset(offset)
    {
    }
};

}

#endif // LINUX_PROCDUMP_COREDUMP_H