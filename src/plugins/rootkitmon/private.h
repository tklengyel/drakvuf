/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#ifndef ROOTKITMON_PRIVATE_H
#define ROOTKITMON_PRIVATE_H

namespace rootkitmon_ns
{
// PDEVICE_OBJECT
using device_t  = addr_t;
// LDR_DATA_TABLE_ENTRY of the driver
using driver_t  = addr_t;
using device_stack_t = std::unordered_map<device_t, std::vector<device_t>>;
using sha256_checksum_t = std::array<uint8_t, 32>;

enum
{
    EPROCESS_UNIQUE_PROCESS_ID,
    LDR_DATA_TABLE_ENTRY_DLLBASE,
    LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE,
    LDR_DATA_TABLE_ENTRY_BASEDLLNAME,
    OBJECT_DIRECTORY_ENTRY_CHAINLINK,
    OBJECT_DIRECTORY_ENTRY_OBJECT,
    OBJECT_HEADER_TYPEINDEX,
    OBJECT_HEADER_INFOMASK,
    OBJECT_HEADER_NAME_INFO_NAME,
    OBJECT_TYPE_NAME,
    OBJECT_TYPE_TYPE_INFO,
    OBJECT_TYPE_CALLBACKLIST,
    DRIVER_OBJECT_DEVICEOBJECT,
    DRIVER_OBJECT_STARTIO,
    DRIVER_OBJECT_DRIVERNAME,
    DRIVER_OBJECT_FASTIODISPATCH,
    DEVICE_OBJECT_ATTACHEDDEVICE,
    DEVICE_OBJECT_DRIVEROBJECT,
    DEVICE_OBJECT_NEXTDEVICE,
    __OFFSET_MAX
};

static const char* offset_names[__OFFSET_MAX][2] =
{
    [EPROCESS_UNIQUE_PROCESS_ID] = {"_EPROCESS", "UniqueProcessId"},
    [LDR_DATA_TABLE_ENTRY_DLLBASE] = { "_LDR_DATA_TABLE_ENTRY", "DllBase" },
    [LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE] = { "_LDR_DATA_TABLE_ENTRY", "SizeOfImage" },
    [LDR_DATA_TABLE_ENTRY_BASEDLLNAME] = { "_LDR_DATA_TABLE_ENTRY", "BaseDllName" },
    [OBJECT_DIRECTORY_ENTRY_CHAINLINK] = { "_OBJECT_DIRECTORY_ENTRY", "ChainLink" },
    [OBJECT_DIRECTORY_ENTRY_OBJECT] = { "_OBJECT_DIRECTORY_ENTRY", "Object" },
    [OBJECT_HEADER_TYPEINDEX] = { "_OBJECT_HEADER", "TypeIndex" },
    [OBJECT_HEADER_INFOMASK] = { "_OBJECT_HEADER", "InfoMask" },
    [OBJECT_HEADER_NAME_INFO_NAME] = { "_OBJECT_HEADER_NAME_INFO", "Name" },
    [OBJECT_TYPE_NAME] = { "_OBJECT_TYPE", "Name" },
    [OBJECT_TYPE_TYPE_INFO] = { "_OBJECT_TYPE", "TypeInfo" },
    [OBJECT_TYPE_CALLBACKLIST] = { "_OBJECT_TYPE", "CallbackList" },
    [DRIVER_OBJECT_DEVICEOBJECT] = { "_DRIVER_OBJECT", "DeviceObject" },
    [DRIVER_OBJECT_STARTIO] = { "_DRIVER_OBJECT", "DriverStartIo" },
    [DRIVER_OBJECT_DRIVERNAME] = { "_DRIVER_OBJECT", "DriverName" },
    [DRIVER_OBJECT_FASTIODISPATCH] = { "_DRIVER_OBJECT", "FastIoDispatch" },
    [DEVICE_OBJECT_ATTACHEDDEVICE] = { "_DEVICE_OBJECT", "AttachedDevice" },
    [DEVICE_OBJECT_DRIVEROBJECT] = { "_DEVICE_OBJECT", "DriverObject" },
    [DEVICE_OBJECT_NEXTDEVICE] = { "_DEVICE_OBJECT", "NextDevice" },
};

static constexpr uint32_t mem_not_paged = 0x08000000;
static constexpr uint32_t mem_execute = 0x20000000;
static constexpr uint32_t mem_write = 0x80000000;

struct section_header_t
{
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_raw_data;
    uint32_t ptr_raw_data;
    uint32_t ptr_relocs;
    uint32_t ptr_line_numbers;
    uint16_t num_relocs;
    uint16_t num_line_numbers;
    uint32_t characteristics;

    inline std::string get_name() const
    {
        return { name, 8 };
    }
};
static_assert(40 == sizeof(section_header_t), "Section header size mismatch");

struct file_header_t
{
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timedatestamp;
    uint32_t ptr_symbol_table;
    uint32_t num_symbols;
    uint16_t size_optional_header;
    uint16_t characteristics;
};
static_assert(20 == sizeof(file_header_t), "File header size mismatch");

struct optional_header_t
{
    uint16_t magic;
    uint8_t  major_version;
    uint8_t  minor_version;
    uint32_t size_code;
    uint32_t size_init_data;
    uint32_t size_uninit_data;
    uint32_t entry_point;
    uint32_t base_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_image;
    uint32_t size_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_stack_reserve;
    uint64_t size_stack_commit;
    uint64_t size_heap_reserve;
    uint64_t size_heap_commit;
    uint32_t loader_flags;
    uint32_t num_rva_sizes;
    uint64_t data_directories[16];
};
static_assert(240 == sizeof(optional_header_t), "Optional header size mismatch");

struct nt_headers_t
{
    uint32_t           signature;
    file_header_t      file_header;
    optional_header_t  optional_header;

    inline const section_header_t* get_section(int n) const
    {
        if (n >= file_header.num_sections)
            return nullptr;

        auto data = reinterpret_cast<uint64_t>(&optional_header) + file_header.size_optional_header;
        auto sections = reinterpret_cast<const section_header_t*>(data);
        return &sections[n];
    }
};
static_assert(4 + 20 + 240 == sizeof(nt_headers_t), "NT headers size mismatch");

struct dos_header_t
{
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[ 4 ];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[ 10 ];
    uint32_t e_lfanew;

    inline const nt_headers_t* get_nt_headers() const
    {
        return reinterpret_cast<const nt_headers_t*>((uint64_t)this + e_lfanew);
    }
};
static_assert(64 == sizeof(dos_header_t), "Dos header size mismatch");

struct checksum_data_t
{
    addr_t virtual_address;
    addr_t virtual_size;
    sha256_checksum_t checksum;
};

union gdt_entry_t
{
    uint64_t entry;
    struct
    {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t  base_mid;
        uint8_t  type : 4;
        uint8_t  s    : 1;
        uint8_t  dpl  : 2;
        uint8_t  present : 1;
        uint8_t  limit_high : 4;
        uint8_t  avail: 1;
        uint8_t  l    : 1;
        uint8_t  d    : 1;
        uint8_t  g    : 1;
        uint8_t  base_high;
    };
};
static_assert(8 == sizeof(gdt_entry_t), "Generic segment descriptor size mismatch");

struct descriptors_t
{
    addr_t idtr_base;
    addr_t idtr_limit;
    sha256_checksum_t idt_checksum;
    addr_t gdtr_base;
    addr_t gdtr_limit;
    // Pair of descriptor entry VA and its parsed entry
    std::vector<std::pair<addr_t, gdt_entry_t>> gdt;
};

}

#endif
