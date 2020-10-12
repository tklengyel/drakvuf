/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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

#ifndef PROCDUMP_MINIDUMP_H
#define PROCDUMP_MINIDUMP_H

#include <algorithm>
#include <array>
#include <string>
#include <vector>


using std::array;
using std::vector;
using std::wstring;

using rva_t = uint32_t;
using rva64_t = uint64_t;

#define MDMP_VENDOR_ID_SIZE 3
#define MDMP_STRING_MAX_LENGTH 32
#define MDMP_NUMBER_OF_STREAMS 3
#define MDMP_MAX_MEMORY_RANGES 256
#define MDMP_MAX_THREADS 1

enum mdmp_type
{
    MiniDumpNormal         = 0,
    MiniDumpWithFullMemory = 2,
};

struct __attribute__ ((packed, aligned(4)))  mdmp_header
{
    uint32_t signature;            // 'MDMP' byte sequence in binary file
    uint32_t version;
    uint32_t number_of_streams;
    rva_t    stream_directory_rva; // The offset of an array of MINIDUMP_DIRECTORY structures
    uint32_t checksum;             // Could be zero
    uint32_t time_date_stamp;      // time_t: number of seconds from POSIX epoch
    uint64_t flags;                // MINIDUMP_TYPE flags

    mdmp_header(uint32_t number_of_streams, uint32_t time_date_stamp)
        : signature('PMDM')
        , version(0x61b1a793)
        , number_of_streams(number_of_streams)
        , stream_directory_rva(sizeof(struct mdmp_header))
        , checksum(0)
        , time_date_stamp(time_date_stamp)
        , flags(MiniDumpNormal)
    {
    }
};

enum mdmp_stream_type
{
    ThreadListStream            = 3,
    ModuleListStream            = 4,
    MemoryListStream            = 5,
    SystemInfoStream            = 7,
    Memory64ListStream          = 9,
};

struct __attribute__ ((packed, aligned(4)))  mdmp_location_descriptor
{
    uint32_t data_size;
    rva_t    rva;
};

struct __attribute__ ((packed, aligned(4)))  mdmp_directory
{
    uint32_t                            stream_type;  // One of MINIDUMP_STREAM_TYPE
    struct mdmp_location_descriptor location;
};

struct __attribute__ ((packed, aligned(4)))  mdmp_system_info
{
    enum
    {
        PROCESSOR_ARCHITECTURE_INTEL = 0,
        PROCESSOR_ARCHITECTURE_AMD64 = 9,
    };

    enum
    {
        PROCESSOR_INTEL_PENTIUM_II = 6,
    };

    enum
    {
        VER_NT_WORKSTATION       = 1,
    };

    enum
    {
        VER_PLATFORM_WIN32_NT = 2,
    };

    uint16_t processor_architecture;
    uint16_t processor_level;
    uint16_t processor_revision;
    uint8_t  number_of_processors;
    uint8_t  product_type;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t build_number;
    uint32_t platform_id;
    rva_t    csdversion_rva;
    union
    {
        uint32_t reserved_1;
        struct
        {
            uint16_t suite_mask;
            uint16_t reserved_2;
        };
    };
    union __attribute__ ((packed, aligned(4))) cpu_information
    {
        struct __attribute__((packed, aligned(4)))
        {
            uint32_t vendor_id[MDMP_VENDOR_ID_SIZE]; // CPUID.0
            uint32_t version_information; // CPUID.1.EAX
            uint32_t feature_information; // CPUID.1.EDX
            uint32_t amd_extended_cpu_features; // CPUID.80000001.EBX
        } x86_cpu_info;
    } cpu;

    mdmp_system_info(bool is32bit, uint8_t number_of_cpus, uint32_t major, uint32_t minor, uint32_t build, rva_t csdversion_rva, array<uint32_t, MDMP_VENDOR_ID_SIZE> cpu_vendor, uint32_t cpu_version, uint32_t cpu_features, uint32_t cpu_ext_features)
        : processor_architecture(is32bit ? PROCESSOR_ARCHITECTURE_INTEL : PROCESSOR_ARCHITECTURE_AMD64)
        , processor_level(get_family_from_cpu_version(cpu_version))
        , processor_revision(get_revision_from_cpu_version(cpu_version))
        , number_of_processors(number_of_cpus)
        , product_type(VER_NT_WORKSTATION)
        , major_version(major)
        , minor_version(minor)
        , build_number(build)
        , platform_id(VER_PLATFORM_WIN32_NT)
        , csdversion_rva(csdversion_rva)
        , cpu()
    {
        for (int i = 0; i < 3; ++i)
            cpu.x86_cpu_info.vendor_id[i] = cpu_vendor[i];

        cpu.x86_cpu_info.version_information = cpu_version;
        cpu.x86_cpu_info.feature_information = cpu_features;
        cpu.x86_cpu_info.amd_extended_cpu_features = cpu_ext_features;
    }

private:
    uint16_t get_family_from_cpu_version(uint32_t v)
    {
        return (v >> 8) & 0xf;
    }

    uint16_t get_revision_from_cpu_version(uint32_t v)
    {
        union
        {
            uint64_t value;
            struct
            {
                uint8_t stepping;
                uint8_t model;
            };
        } r;
        r.stepping = v & 0xf;
        r.model = (v >> 4) & 0xf;

        return r.value;
    }
};

struct __attribute__ ((packed, aligned(4))) mdmp_string
{
    uint32_t length;
    // To simplify coding replace variable length array with fixed sized
    array<wchar_t, MDMP_STRING_MAX_LENGTH> buffer;

    mdmp_string(wstring& service_pack)
        : length(0)
        , buffer{0}
    {
        if (service_pack.size() >= MDMP_STRING_MAX_LENGTH)
            return;

        length = service_pack.size();
        for (uint32_t i = 0; i < length; ++i)
            buffer[i] = service_pack[i];
    }
};

struct __attribute__ ((packed, aligned(4))) mdmp_memory_descriptor
{
    uint64_t start_of_memory_range;
    struct mdmp_location_descriptor memory;
};

struct __attribute__ ((packed, aligned(4))) reg_m128a
{
    uint64_t low;
    int64_t  high;
};

enum context_flags_x86
{
    CONTEXT_X86_CONTROL  = 0x10001,
    CONTEXT_X86_INTEGER  = 0x10002,
    CONTEXT_X86_SEGMENTS = 0x10004,
};

enum context_flags_x64
{
    CONTEXT_X64_CONTROL  = 0x100001,
    CONTEXT_X64_INTEGER  = 0x100002,
    CONTEXT_X64_SEGMENTS = 0x100004,
};

struct __attribute__ ((packed, aligned(4))) context_x86
{

    uint32_t   context_flags;
    uint32_t   dr0;
    uint32_t   dr1;
    uint32_t   dr2;
    uint32_t   dr3;
    uint32_t   dr6;
    uint32_t   dr7;
    struct __attribute__ ((packed, aligned(4)))
    {
        uint32_t   control_word;
        uint32_t   status_word;
        uint32_t   tag_word;
        uint32_t   error_offset;
        uint32_t   error_selector;
        uint32_t   data_offset;
        uint32_t   data_selector;
        uint8_t    register_area[80];
        uint32_t   cr0_npx_state;
    } float_save;
    uint32_t   seg_gs;
    uint32_t   seg_fs;
    uint32_t   seg_es;
    uint32_t   seg_ds;
    uint32_t   edi;
    uint32_t   esi;
    uint32_t   ebx;
    uint32_t   edx;
    uint32_t   ecx;
    uint32_t   eax;
    uint32_t   ebp;
    uint32_t   eip;
    uint32_t   seg_cs;
    uint32_t   eflags;
    uint32_t   esp;
    uint32_t   seg_ss;
    uint8_t    extended_registers[512];
};

struct __attribute__ ((packed, aligned(4))) context_x64
{
    uint64_t p1_home;
    uint64_t p2_home;
    uint64_t p3_home;
    uint64_t p4_home;
    uint64_t p5_home;
    uint64_t p6_home;
    uint32_t context_flags;
    uint32_t mx_csr;
    uint16_t seg_cs;
    uint16_t seg_ds;
    uint16_t seg_es;
    uint16_t seg_fs;
    uint16_t seg_gs;
    uint16_t seg_ss;
    uint32_t eflags;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    union
    {
        // struct XMM_SAVE_AREA32 FltSave;
        struct
        {
            struct reg_m128a header[2];
            struct reg_m128a legacy[8];
            struct reg_m128a xmm0;
            struct reg_m128a xmm1;
            struct reg_m128a xmm2;
            struct reg_m128a xmm3;
            struct reg_m128a xmm4;
            struct reg_m128a xmm5;
            struct reg_m128a xmm6;
            struct reg_m128a xmm7;
            struct reg_m128a xmm8;
            struct reg_m128a xmm9;
            struct reg_m128a xmm10;
            struct reg_m128a xmm11;
            struct reg_m128a xmm12;
            struct reg_m128a xmm13;
            struct reg_m128a xmm14;
            struct reg_m128a xmm15;
        };
    };
    struct reg_m128a vector_register[26];
    uint64_t vector_control;
    uint64_t debug_control;
    uint64_t last_branch_to_rip;
    uint64_t last_branch_from_rip;
    uint64_t last_exception_to_rip;
    uint64_t last_exception_from_rip;
};

// CONTEXT_Xxx_CONTROL specifies seg_ss, rsp, seg_cs, rip, and eflags.
// CONTEXT_Xxx_INTEGER specifies rax, rcx, rdx, rbx, rbp, rsi, rdi, and r8-r15.
// CONTEXT_Xxx_SEGMENTS specifies seg_ds, seg_es, seg_fs, and seg_gs.

union thread_context
{
    struct context_x86 ctx_86;
    struct context_x64 ctx_64;

    void set(bool is32bit, x86_registers_t* regs)
    {
        if (is32bit)
        {
            ctx_86.context_flags = CONTEXT_X86_CONTROL | CONTEXT_X86_INTEGER | CONTEXT_X86_SEGMENTS;

            ctx_86.seg_cs = regs->cs_sel;
            ctx_86.seg_ds = regs->ds_sel;
            ctx_86.seg_es = regs->es_sel;
            ctx_86.seg_fs = regs->fs_sel;
            ctx_86.seg_gs = regs->gs_sel;
            ctx_86.seg_ss = regs->ss_sel;

            ctx_86.esp = regs->rsp;
            ctx_86.eip = regs->rip;
            ctx_86.eflags = regs->rflags;

            ctx_86.eax = regs->rax;
            ctx_86.ecx = regs->rcx;
            ctx_86.edx = regs->rdx;
            ctx_86.ebx = regs->rbx;
            ctx_86.ebp = regs->rbp;
            ctx_86.edi = regs->rdi;
            ctx_86.esi = regs->rsi;
        }
        else
        {
            ctx_64.context_flags = CONTEXT_X86_CONTROL | CONTEXT_X86_INTEGER | CONTEXT_X86_SEGMENTS;

            ctx_64.seg_cs = regs->cs_sel;
            ctx_64.seg_ds = regs->ds_sel;
            ctx_64.seg_es = regs->es_sel;
            ctx_64.seg_fs = regs->fs_sel;
            ctx_64.seg_gs = regs->gs_sel;
            ctx_64.seg_ss = regs->ss_sel;

            ctx_64.rsp = regs->rsp;
            ctx_64.rip = regs->rip;
            ctx_64.eflags = regs->rflags;

            ctx_64.rax = regs->rax;
            ctx_64.rcx = regs->rcx;
            ctx_64.rdx = regs->rdx;
            ctx_64.rbx = regs->rbx;
            ctx_64.rbp = regs->rbp;
            ctx_64.rdi = regs->rdi;
            ctx_64.rsi = regs->rsi;
            ctx_64.r8  = regs->r8;
            ctx_64.r9  = regs->r9;
            ctx_64.r10 = regs->r10;
            ctx_64.r11 = regs->r11;
            ctx_64.r12 = regs->r12;
            ctx_64.r13 = regs->r13;
            ctx_64.r14 = regs->r14;
            ctx_64.r15 = regs->r15;
        }
    }
};

struct __attribute__ ((packed, aligned(4))) mdmp_thread
{
    uint32_t thread_id;
    uint32_t suspend_count;
    uint32_t priority_class;
    uint32_t priority;
    uint64_t teb;
    struct mdmp_memory_descriptor stack;
    struct mdmp_location_descriptor thread_context;

#define NORMAL_PRIORITY_CLASS 0x20
#define THREAD_PRIORITY_NORMAL 0

    mdmp_thread()
        : thread_id(0)
        , suspend_count(-1)
        , priority_class(NORMAL_PRIORITY_CLASS)
        , priority(THREAD_PRIORITY_NORMAL)
        , teb(0)
        , stack()
        , thread_context()
    {
    }
};

struct __attribute__ ((packed, aligned(4))) mdmp_memory_descriptor64
{
    uint64_t start_of_memory_range;
    uint64_t data_size;

    mdmp_memory_descriptor64(uint64_t start = 0, uint64_t size = 0)
        : start_of_memory_range(start)
        , data_size(size) {}
};

/*
 * If number of process's memory ranges exceeds the defined maximum
 * then not all ranges would be described in metadata.
 *
 * Though full memory dump would be present in output file.
 */
struct __attribute__ ((packed, aligned(4))) mdmp_memory_list
{
#ifdef MDMP_64
    uint64_t number_of_memory_ranges;
    rva64_t  base_rva;
    array<struct mdmp_memory_descriptor64, MDMP_MAX_MEMORY_RANGES> memory_ranges;
#else
    uint32_t number_of_memory_ranges;
    array<struct mdmp_memory_descriptor, MDMP_MAX_MEMORY_RANGES> memory_ranges;
#endif

    mdmp_memory_list(rva64_t base_rva, vector<struct mdmp_memory_descriptor64>& ranges)
        : number_of_memory_ranges(std::min(ranges.size(), (size_t)MDMP_MAX_MEMORY_RANGES))
#ifdef MDMP_64
        , base_rva(base_rva)
#endif
        , memory_ranges()
    {
        [[maybe_unused]] rva64_t offset = 0;
        for (size_t i = 0; i < number_of_memory_ranges; ++i)
#ifdef MDMP_64
            memory_ranges[i] = ranges[i];
#else
        {
            memory_ranges[i].start_of_memory_range = ranges[i].start_of_memory_range;
            memory_ranges[i].memory.data_size = ranges[i].data_size;
            memory_ranges[i].memory.rva = base_rva + offset;
            offset += ranges[i].data_size;
        }
#endif

        if (ranges.size() > MDMP_MAX_MEMORY_RANGES)
            PRINT_DEBUG("[PROCDUMP] Warning: Number of memory ranges exceeds "
                        "defined maximum - not all ranges would be described");
    }

    uint32_t size()
    {
        return sizeof(uint32_t) + number_of_memory_ranges * sizeof(struct mdmp_memory_descriptor);
    }

    mdmp_location_descriptor find(uint64_t start_of_memory_range)
    {
#ifdef MDMP_64
        rva64_t rva = base_rva;
#endif
        for (size_t i = 0; i < number_of_memory_ranges; ++i)
            if (start_of_memory_range == memory_ranges[i].start_of_memory_range)
#ifdef MDMP_64
                // TODO What to do if sizes mismatch?
                return {(uint32_t)memory_ranges[i].data_size, (uint32_t)rva};
            else
                rva += memory_ranges[i].data_size;
#else
                return memory_ranges[i].memory;
#endif

        return {0, 0};
    }
};

struct __attribute__ ((packed, aligned(4))) mdmp_thread_list
{
    uint32_t number_of_threads;
    array<struct mdmp_thread, MDMP_MAX_THREADS> threads;
    // This is not part of original structure but used here for convenience
    array<union thread_context, MDMP_MAX_THREADS> contexts;

    mdmp_thread_list(rva64_t rva, bool is32bit,
                     vector<struct mdmp_thread> threads_,
                     vector<union thread_context> contexts_,
                     mdmp_memory_list& memory)
        : number_of_threads(MDMP_MAX_THREADS)
        , threads()
        , contexts()
    {
        for (size_t i = 0; i < std::min(threads.size(), (size_t)MDMP_MAX_THREADS); ++i)
        {
            threads[i] = threads_[i];
            threads[i].stack.memory = memory.find(threads[i].stack.start_of_memory_range);
            threads[i].thread_context.data_size = is32bit ? sizeof(struct context_x86) : sizeof(struct context_x64);
            threads[i].thread_context.rva = rva + offsetof(mdmp_thread_list, contexts) + i * sizeof(union thread_context);
            contexts[i] = contexts_[i];
        }
    }

    uint32_t size()
    {
        return sizeof(uint32_t) + number_of_threads * sizeof(struct mdmp_thread);
    }
};

/*
 * This structure represents metadata placed at the beginning of the dump file.
 * Process's memory dump follows this header. So BaseRva field of
 * MINIDUMP_MEMORY64_LIST equals to size of this structure.
 *
 * To simplify coding all variable sized arrays are replaced with fixed sized.
 * This could be changed in the feature.
 */
struct __attribute__ ((packed, aligned(4))) minidump
{
    struct mdmp_header header;
    array<struct mdmp_directory, MDMP_NUMBER_OF_STREAMS> directories;
    struct mdmp_string csd_version;
    struct mdmp_system_info system_info;
    struct mdmp_memory_list memory_list;
    struct mdmp_thread_list thread_list;

    minidump(uint32_t time_date_stamp,
             bool is32bit,
             uint8_t number_of_cpus,
             uint32_t major,
             uint32_t minor,
             uint32_t build,
             array<uint32_t, MDMP_VENDOR_ID_SIZE> cpu_vendor,
             uint32_t cpu_version,
             uint32_t cpu_features,
             uint32_t cpu_ext_features,
             wstring service_pack,
             vector<struct mdmp_memory_descriptor64> memory_ranges,
             vector<struct mdmp_thread> threads,
             vector<union thread_context> contexts)
        : header(MDMP_NUMBER_OF_STREAMS, time_date_stamp)
        , directories()
        , csd_version(service_pack)
        , system_info(is32bit, number_of_cpus, major, minor, build, offsetof(minidump, csd_version), cpu_vendor, cpu_version, cpu_features, cpu_ext_features)
        , memory_list(sizeof(struct minidump), memory_ranges)
        , thread_list(offsetof(minidump, thread_list), is32bit, threads, contexts, memory_list)
    {
        directories[0].stream_type = SystemInfoStream;
        directories[0].location.data_size = sizeof(struct mdmp_system_info);
        directories[0].location.rva = offsetof(minidump, system_info);

        directories[1].stream_type = ThreadListStream;
        directories[1].location.data_size = thread_list.size();
        directories[1].location.rva = offsetof(minidump, thread_list);

        directories[2].stream_type = MemoryListStream;
        directories[2].location.data_size = memory_list.size();
        directories[2].location.rva = offsetof(minidump, memory_list);
    }
};

#endif // PROCDUMP_MINIDUMP_H
