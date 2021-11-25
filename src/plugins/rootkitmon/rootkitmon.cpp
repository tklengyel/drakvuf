/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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
#include <glib.h>
#include <libvmi/libvmi.h>
#include <unordered_map>
#include <set>
#include "plugins/output_format.h"
#include "rootkitmon.h"
#include "private.h"

std::vector<const char*> hook_targets =
{
    "PspSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "CmpRegisterCallbackInternal",
    "ObRegisterCallbacks",
    "FsRtlRegisterFileSystemFilterCallbacks",
    "IoRegisterContainerNotification",
    "IoRegisterFsRegistrationChange",
    "IoRegisterPlugPlayNotification",
    "IoWMISetNotificationCallback",
    "KeRegisterBugCheckCallback",
    "SeRegisterLogonSessionTerminatedRoutine",
};

static bool translate_ksym2p(vmi_instance_t vmi, const char* symbol, addr_t* addr)
{
    addr_t temp_va;
    if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, symbol, &temp_va))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to translate symbol to virtual address\n");
        return false;
    }
    if (VMI_SUCCESS != vmi_translate_kv2p(vmi, temp_va, addr))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to translate virtual address to physical\n");
        return false;
    }
    return true;
}

static uint64_t align_by_page(uint64_t value)
{
    auto aligned_size   = value & ~(VMI_PS_4KB - 1);
    auto size_remainder = value &  (VMI_PS_4KB - 1);
    if (size_remainder)
        aligned_size += VMI_PS_4KB;
    return aligned_size;
}

/**
 * Enumerate PE sections with mem_execute and mem_not_paged flags.
 * Returns vector of <virtual address, aligned section size>
 */
static std::vector<std::pair<addr_t, size_t>> get_pe_code_sections(void* module, addr_t read_imagebase)
{
    std::vector<std::pair<addr_t, size_t>> out;

    auto dos_h = static_cast<dos_header_t*>(module);
    for (size_t i = 0; i < dos_h->get_nt_headers()->file_header.num_sections; i++)
    {
        auto section = dos_h->get_nt_headers()->get_section(i);
        // Some sections (PAGE, INIT) might not be present in memory, that's why
        // we process only non pagable sections.
        // It is important to check for write access as well since there are sections
        // with RWX access rights on win7 and below. e.g. RWEXEC in hal.dll and ntoskrnl.
        if (section->characteristics & mem_execute
            && section->characteristics & mem_not_paged
            && !(section->characteristics & mem_write))
        {
            auto aligned_size = align_by_page(section->virtual_size);
            out.emplace_back(section->virtual_address + read_imagebase, aligned_size);
        }
    }
    return out;
}

/**
 * Given address and size, calculate SHA256 of a given memory region.
 * Partially taken from memdump plugin.
 */
static sha256_checksum_t calc_checksum(vmi_instance_t vmi, addr_t address, size_t size)
{
    sha256_checksum_t out{ 0 };

    auto aligned_size = align_by_page(size);
    auto intra_page_offset = address & (VMI_PS_4KB - 1);

    auto num_pages = aligned_size / VMI_PS_4KB;

    std::vector<void*> access_ptrs(num_pages, nullptr);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
        .addr = address
    );

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &ctx, num_pages, access_ptrs.data()))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to map guest VA 0x%lx\n", ctx.addr);
        return out;
    }

    auto checksum = g_checksum_new(G_CHECKSUM_SHA256);

    for (size_t i = 0; i < num_pages; i++)
    {
        size_t write_size = size;

        if (write_size > VMI_PS_4KB - intra_page_offset)
            write_size = VMI_PS_4KB - intra_page_offset;

        if (access_ptrs[i])
        {
            g_checksum_update(checksum, (const uint8_t*)access_ptrs[i] + intra_page_offset, write_size);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }

        intra_page_offset = 0;
        size -= write_size;
    }

    size_t buffer_size = out.size();
    g_checksum_get_digest(checksum, out.data(), &buffer_size);

    if (buffer_size != out.size())
    {
        PRINT_DEBUG("[ROOTKITMON] SHA256 checksum digest size mismatch\n");
        throw -1;
    }

    g_checksum_free(checksum);
    return out;
}

/**
 * Enumerate present GDT entries.
 * Returns vector of <virtual address of gdt entry, parsed gdt entry>
*/
static std::vector<std::pair<addr_t, gdt_entry_t>> enumerate_gdt(vmi_instance_t vmi, addr_t gdt_base, size_t gdt_limit)
{
    // address -> gdt_entry_t
    std::vector<std::pair<addr_t, gdt_entry_t>> gdt;

    for (size_t i = 0; i <= gdt_limit; i += sizeof(gdt_entry_t))
    {
        gdt_entry_t entry{};
        // Read uint64_t entry
        if (VMI_SUCCESS != vmi_read_va(vmi, gdt_base + i, 4, sizeof(entry), (void*)&entry, nullptr))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to read GDT entry\n");
            throw -1;
        }

        // Save only present entries
        if (entry.present)
        {
            gdt.emplace_back(gdt_base + i, entry);
        }
    }
    return gdt;
}


/**
 * This is the callback of the fwpkclnt.sys function FwpmCalloutAdd0.
*/
static event_response_t wfp_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<rootkitmon*>(info->trap->data);
    fmt::print(plugin->format, "rootkitmon", drakvuf, info,
        keyval("Reason", fmt::Qstr(info->trap->name)));
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is the callback of the fltmgr.sys function FltRegisterFilter.
*/
static event_response_t flt_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<rootkitmon*>(info->trap->data);
    fmt::print(plugin->format, "rootkitmon", drakvuf, info,
        keyval("Reason", fmt::Qstr(info->trap->name)));
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is the callback of the memory trap.
 * If an instruction writes into the page where HalPrivateDispatchTable located, this callback is executed.
*/
static event_response_t halprivatetable_overwrite_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<rootkitmon*>(info->trap->data);
    // Table size is unknown, assume 0x100 bytes
    if (info->trap_pa >= plugin->halprivatetable && info->trap_pa < plugin->halprivatetable + 0x100)
    {
        fmt::print(plugin->format, "rootkitmon", drakvuf, info,
            keyval("Reason", fmt::Qstr("HalPrivateDispatchTable overwrite")));
    }
    return VMI_EVENT_RESPONSE_NONE;
}

bool rootkitmon::enumerate_cores(vmi_instance_t vmi)
{
    for (size_t vcpu = 0; vcpu < vmi_get_num_vcpus(vmi); vcpu++)
    {
        uint64_t idtr_base = 0, gdtr_base = 0;
        uint64_t idtr_limit = 0, gdtr_limit = 0;
        uint64_t lstar = 0;

        if (VMI_SUCCESS == vmi_get_vcpureg(vmi, &idtr_base, IDTR_BASE, vcpu) &&
            VMI_SUCCESS == vmi_get_vcpureg(vmi, &idtr_limit, IDTR_LIMIT, vcpu) &&
            VMI_SUCCESS == vmi_get_vcpureg(vmi, &gdtr_base, GDTR_BASE, vcpu) &&
            VMI_SUCCESS == vmi_get_vcpureg(vmi, &gdtr_limit, GDTR_LIMIT, vcpu) &&
            VMI_SUCCESS == vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, vcpu))
        {
            PRINT_DEBUG("[ROOTKITMON] [VCPU] %zu IDTR 0x%lx:0x%lx\n", vcpu, idtr_base, idtr_limit);
            PRINT_DEBUG("[ROOTKITMON] [VCPU] %zu GDTR 0x%lx:0x%lx\n", vcpu, gdtr_base, gdtr_limit);
            PRINT_DEBUG("[ROOTKITMON] [VCPU] %zu LSTAR 0x%lx\n", vcpu, lstar);

            // Calculate IDT checksum
            auto idt_checksum = calc_checksum(vmi, idtr_base, idtr_limit + 1);

            // Enumerate GDT entries
            auto gdt = enumerate_gdt(vmi, gdtr_base, gdtr_limit);

            // Save descriptor values
            this->descriptors[vcpu] =
            {
                idtr_base,
                idtr_limit,
                idt_checksum,
                gdtr_base,
                gdtr_limit,
                gdt
            };

            // Save msr value
            this->msr_lstar[vcpu] = lstar;
        }
        else
        {
            return false;
        }
    }
    return true;
}

/**
 * This callback is executed on every discovered driver.
 * It is used to calculate checksums of driver sections.
 * @driver - LDR_DATA_TABLE_ENTRY pointer.
*/
static void driver_visitor(drakvuf_t drakvuf, addr_t driver, void* ctx)
{
    auto plugin = static_cast<rootkitmon*>(ctx);
    addr_t imagebase;
    vmi_lock_guard vmi(drakvuf);
    // Read driver image base
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, driver + plugin->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], 4, &imagebase))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to read driver image base\n");
        throw -1;
    }

    ACCESS_CONTEXT(a_ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
        .addr = imagebase
    );

    // Map 1 4KB page with PE header
    void* module = nullptr;
    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &a_ctx, 1, &module))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to map guest VA 0x%lx\n", a_ctx.addr);
        return;
    }

    // Checksum every section and save it into `driver_sections_checksums`
    for (const auto& [virt_addr, virt_size] : get_pe_code_sections(module, imagebase))
    {
        auto aligned_size = align_by_page(virt_size);

        checksum_data_t data =
        {
            .virtual_address = virt_addr,
            .virtual_size = aligned_size,
            .checksum = calc_checksum(vmi, virt_addr, aligned_size)
        };
        plugin->driver_sections_checksums[driver].push_back(data);

    }
    munmap(module, VMI_PS_4KB);
}


void rootkitmon::check_driver_integrity(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto past_drivers_checksums = std::move(this->driver_sections_checksums);
    this->driver_sections_checksums.clear();
    // Collect new checksums
    drakvuf_enumerate_drivers(drakvuf, driver_visitor, static_cast<void*>(this));
    // Compare
    for (const auto& [driver, infos] : this->driver_sections_checksums)
    {
        // Find driver object
        if (past_drivers_checksums.find(driver) == past_drivers_checksums.end())
            continue;

        const auto& p_infos = past_drivers_checksums[driver];

        for (const auto& checksum_data : infos)
        {
            for (const auto& p_checksum_data : p_infos)
            {
                if (checksum_data.virtual_address == p_checksum_data.virtual_address)
                {
                    if (checksum_data.checksum != p_checksum_data.checksum)
                    {
                        {
                            vmi_lock_guard vmi(drakvuf);
                            unicode_string_t* drvname = drakvuf_read_unicode_va(vmi, driver + this->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], 4);
                            if (drvname)
                            {
                                fmt::print(this->format, "rootkitmon", drakvuf, info,
                                    keyval("Reason", fmt::Qstr("Driver section modification")),
                                    keyval("Driver", fmt::Qstr((const char*)drvname->contents)));
                                vmi_free_unicode_str(drvname);
                            }
                            else
                            {
                                fmt::print(this->format, "rootkitmon", drakvuf, info,
                                    keyval("Reason", fmt::Qstr("Driver section modification")),
                                    keyval("Driver", fmt::Qstr("Unknown")));
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
}

void rootkitmon::check_driver_objects(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto past_driver_object_checksums = std::move(this->driver_object_checksums);
    auto past_driver_stacks = std::move(this->driver_stacks);
    this->driver_object_checksums.clear();
    this->driver_stacks.clear();
    // Collect new info
    {
        vmi_lock_guard vmi(drakvuf);
        if (!this->is32bit)
            for (const auto& drv_object : this->enumerate_driver_objects(vmi))
            {
                this->driver_object_checksums[drv_object] = calc_checksum(vmi, drv_object + this->offsets[DRIVER_OBJECT_STARTIO], this->guest_ptr_size * 30);
                this->driver_stacks[drv_object] = this->enumerate_driver_stacks(vmi, drv_object);
            }
    }
    // Compare dispatch table checksums
    for (const auto& [drv_object, checksum] : this->driver_object_checksums)
    {
        // Find driver object
        if (past_driver_object_checksums.find(drv_object) == past_driver_object_checksums.end())
            continue;

        const auto& p_checksum = past_driver_object_checksums[drv_object];

        if (checksum != p_checksum)
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("Driver object modification")));
        }
    }
    // Compare driver stacks
    for (const auto& [drv_object, dev_stacks] : this->driver_stacks)
    {
        // Find driver object
        if (past_driver_stacks.find(drv_object) == past_driver_stacks.end())
            continue;

        auto& p_dev_stacks = past_driver_stacks[drv_object];

        for (const auto& [dev_object, dev_stack] : dev_stacks)
        {
            // Find device object
            if (p_dev_stacks.find(dev_object) == p_dev_stacks.end())
                continue;

            const auto& p_dev_stack = p_dev_stacks[dev_object];

            // Size mismatch == stack modification
            if (p_dev_stack.size() != dev_stack.size())
            {
                fmt::print(this->format, "rootkitmon", drakvuf, info,
                    keyval("Reason", fmt::Qstr("Driver stack modification")));
                continue;
            }

            for (size_t i = 0; i < dev_stack.size(); i++)
            {
                // Dev object hijack
                if (dev_stack[i] != p_dev_stack[i])
                {
                    fmt::print(this->format, "rootkitmon", drakvuf, info,
                        keyval("Reason", fmt::Qstr("Driver stack modification")));
                    break;
                }
            }
        }
    }
}

void rootkitmon::check_descriptors(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto past_descriptors = std::move(this->descriptors);
    auto past_lstar = std::move(this->msr_lstar);
    this->descriptors.clear();
    this->msr_lstar.clear();
    {
        vmi_lock_guard vmi(drakvuf);
        if (!enumerate_cores(vmi))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to enumerate descriptors\n");
            throw -1;
        }
    }
    for (const auto& [vcpu, desc_info] : this->descriptors)
    {
        const auto& t_desc_info = past_descriptors[vcpu];
        if (desc_info.idtr_base != t_desc_info.idtr_base)
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("IDTR base modification")));
            break;
        }
        if (desc_info.idt_checksum != t_desc_info.idt_checksum)
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("IDT modification")));
            break;
        }
    }

    for (const auto& [vcpu, desc_info] : this->descriptors)
    {
        const auto& t_desc_info = past_descriptors[vcpu];
        if (desc_info.gdtr_base != t_desc_info.gdtr_base)
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("GDTR base modification")));
            break;
        }
        if (desc_info.gdt.size() != t_desc_info.gdt.size())
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("GDT modification")));
            break;
        }
        else
        {
            for (size_t i = 0; i < desc_info.gdt.size(); i++)
            {
                const auto& [addr, entry] = desc_info.gdt[i];
                const auto& [t_addr, t_entry] = t_desc_info.gdt[i];

                if (addr != t_addr)
                {
                    fmt::print(this->format, "rootkitmon", drakvuf, info,
                        keyval("Reason", fmt::Qstr("GDT modification")));
                    break;
                }
            }
        }
    }
    for (const auto& [vcpu, lstar] : this->msr_lstar)
    {
        if (past_lstar[vcpu] != lstar)
        {
            fmt::print(this->format, "rootkitmon", drakvuf, info,
                keyval("Reason", fmt::Qstr("LSTAR modification")));
        }
    }
}
/**
 * This trap is used to make final analysis.
*/
event_response_t rootkitmon::final_check_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // Process only first callback call
    if (is_stopping() && !done_final_analysis)
    {
        PRINT_DEBUG("[ROOTKITMON] Making final analysis\n");

        check_driver_integrity(drakvuf, info);
        check_driver_objects(drakvuf, info);
        check_descriptors(drakvuf, info);

        done_final_analysis = true;
    }
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t rootkitmon::callback_hooks_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    fmt::print(this->format, "rootkitmon", drakvuf, info,
        keyval("Reason", fmt::Qstr(info->trap->name)));
    return VMI_EVENT_RESPONSE_NONE;
}

std::unique_ptr<libhook::ManualHook> rootkitmon::register_profile_hook(drakvuf_t drakvuf, const char* profile, const char* dll_name,
    const char* func_name, hook_cb_t callback)
{
    addr_t func_rva = 0;
    auto profile_json = json_object_from_file(profile);
    if (!profile_json)
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to load JSON debug info for %s\n", dll_name);
        throw -1;
    }
    if (!json_get_symbol_rva(drakvuf, profile_json, func_name, &func_rva))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to find %s RVA in json for %s\n", func_name, dll_name);
        throw -1;
    }

    json_object_put(profile_json);

    auto trap = new drakvuf_trap_t();
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 4;
    trap->breakpoint.addr_type = ADDR_RVA;
    trap->breakpoint.module = dll_name;
    trap->breakpoint.rva = func_rva;
    trap->type = BREAKPOINT;
    trap->data = (void*)this;
    trap->ah_cb = nullptr;
    trap->name = func_name;
    trap->cb = callback;
    trap->ttl = UNLIMITED_TTL;

    auto hook = createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });
    if (!hook)
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to hook %s\n", func_name);
        throw -1;
    }
    else
    {
        return hook;
    }
}

std::unique_ptr<libhook::ManualHook> rootkitmon::register_mem_hook(hook_cb_t callback, addr_t pa, vmi_mem_access_t access)
{
    auto trap = new drakvuf_trap_t();
    trap->type = MEMACCESS;
    trap->memaccess.gfn = pa >> 12;
    trap->memaccess.type = PRE;
    trap->memaccess.access = access;
    trap->data = (void*)this;
    trap->name = nullptr;
    trap->ttl = UNLIMITED_TTL;
    trap->ah_cb = nullptr;
    trap->cb = callback;

    auto hook = createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });
    if (!hook)
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to hook 0x%lx\n", pa >> 12);
        throw -1;
    }
    else
    {
        return hook;
    }
}

std::unique_ptr<libhook::ManualHook> rootkitmon::register_reg_hook(hook_cb_t callback, register_t reg)
{
    auto trap = new drakvuf_trap_t();
    trap->type = REGISTER;
    trap->reg = reg;
    trap->data = (void*)this;
    trap->ah_cb = nullptr;
    trap->name = nullptr;
    trap->cb = callback;
    trap->ttl = UNLIMITED_TTL;

    auto hook = createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });
    if (!hook)
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to hook register\n");
        throw -1;
    }
    else
    {
        return hook;
    }
}

unicode_string_t* rootkitmon::get_object_type_name(vmi_instance_t vmi, addr_t object)
{
    addr_t ob_header = object - this->object_header_size + this->guest_ptr_size;
    uint8_t type_index;

    // Object header is always present before actual object
    if (VMI_SUCCESS != vmi_read_8_va(vmi, ob_header + this->offsets[OBJECT_HEADER_TYPEINDEX], 4, &type_index))
        return nullptr;

    // https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a
    // Due to security mitigations type_index is no longer equals to index in ObTypeIndexTable array on win 10
    // but calculated as following:
    if (this->winver == VMI_OS_WINDOWS_10)
        type_index = type_index ^ ((ob_header >> 8) & 0xff) ^ this->ob_header_cookie;

    addr_t ob_type;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, this->type_idx_table + type_index * this->guest_ptr_size, 4, &ob_type))
        return nullptr;

    return drakvuf_read_unicode_va(vmi, ob_type + this->offsets[OBJECT_TYPE_NAME], 4);
}


std::set<driver_t> rootkitmon::enumerate_directory(vmi_instance_t vmi, addr_t directory)
{
    std::set<driver_t> out;

    // There is only 37 _OBJECT_DIRECTORY_ENTRY entries in object directory:
    // 0: kd> dt nt!_OBJECT_DIRECTORY
    //    +0x000 HashBuckets      : [37] Ptr64 _OBJECT_DIRECTORY_ENTRY
    //    +0x128 Lock             : _EX_PUSH_LOCK
    //    ...
    for (int i = 0; i < 37; i++)
    {
        addr_t hashbucket = 0;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, directory + this->guest_ptr_size * i, 4, &hashbucket) || !hashbucket)
            continue;

        while (true)
        {
            addr_t object = 0;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, hashbucket + this->offsets[OBJECT_DIRECTORY_ENTRY_OBJECT], 4, &object) || !object)
                break;

            unicode_string_t* obj_name = get_object_type_name(vmi, object);
            if (obj_name)
            {
                if (!strcmp((const char*)obj_name->contents, "Driver"))
                    out.insert(object);

                if (!strcmp((const char*)obj_name->contents, "Directory"))
                    for (auto obj : enumerate_directory(vmi, object))
                        out.insert(obj);

                vmi_free_unicode_str(obj_name);
            }

            if (VMI_SUCCESS != vmi_read_addr_va(vmi, hashbucket + this->offsets[OBJECT_DIRECTORY_ENTRY_CHAINLINK], 4, &hashbucket) || !hashbucket)
                break;
        }
    }
    return out;
}

std::set<driver_t> rootkitmon::enumerate_driver_objects(vmi_instance_t vmi)
{
    // Get root directory object VA
    addr_t root_directory_object;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "ObpRootDirectoryObject", &root_directory_object))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to translate ObpRootDirectoryObject to VA\n");
        throw -1;
    }

    // Enumerate directories recursively
    return enumerate_directory(vmi, root_directory_object);
}


/**
 * Every driver can have N number of devices. Every device can be attached to a different device of a different driver,
 * hence the name driver stack.
 * The device object that is pointed to by the AttachedDevice member of _DEVICE_OBJECT structure typically is
 * the device object of a filter driver, which intercepts I/O requests originally targeted to the device
 * represent by the device object.
*/
device_stack_t rootkitmon::enumerate_driver_stacks(vmi_instance_t vmi, addr_t driver_object)
{
    device_stack_t stacks;

    // Read first device object
    addr_t device_object;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, driver_object + offsets[DRIVER_OBJECT_DEVICEOBJECT], 4, &device_object))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to read device object\n");
        throw -1;
    }

    // Loop over `NextDevice` member of _DEVICE_OBJECT structure
    while (device_object)
    {
        // Read first attached device
        addr_t attached_device;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, device_object + offsets[DEVICE_OBJECT_ATTACHEDDEVICE], 4, &attached_device))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to read AttachedDevice object\n");
            throw -1;
        }

        // Loop over `AttachedDevice` member of _DEVICE_OBJECT structure
        while (attached_device)
        {
            // Save into the stack of a `device_object`
            stacks[device_object].push_back(attached_device);

            // Read next `AttachedDevice`
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, attached_device + offsets[DEVICE_OBJECT_ATTACHEDDEVICE], 4, &attached_device))
            {
                PRINT_DEBUG("[ROOTKITMON] Failed to read AttachedDevice\n");
                throw -1;
            }
        }

        // Read next `NextDevice`
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, device_object + offsets[DEVICE_OBJECT_NEXTDEVICE], 4, &device_object))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to read next device object\n");
            throw -1;
        }
    }
    return stacks;
}

rootkitmon::rootkitmon(drakvuf_t drakvuf, const rootkitmon_config* config, output_format_t output)
    : pluginex(drakvuf, output), format(output), offsets(new size_t[__OFFSET_MAX]),
      done_final_analysis(false), not_supported(false)
{
    if (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E)
    {
        this->guest_ptr_size = 4;
        this->is32bit = true;
    }
    else
    {
        this->guest_ptr_size = 8;
        this->is32bit = false;
    }

    {
        vmi_lock_guard vmi(drakvuf);
        win_build_info_t build_info;
        if (!vmi_get_windows_build_info(vmi.vmi, &build_info))
            throw -1;

        this->winver = build_info.version;
    }

    for (const auto& target : hook_targets)
    {
        auto hook = createSyscallHook(target, &rootkitmon::callback_hooks_cb);
        if (!hook)
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to hook %s\n", target);
        }
        else
        {
            hook->trap_->name = target;
            this->syscall_hooks.push_back(std::move(hook));
        }
    }

    if (!config->fwpkclnt_profile)
    {
        PRINT_DEBUG("[ROOTKITMON] No profile for fwpkclnt.sys was given!\n");
    }
    else
    {
        manual_hooks.push_back(register_profile_hook(drakvuf, config->fwpkclnt_profile, "fwpkclnt.sys", "FwpmCalloutAdd0", wfp_cb));
    }

    if (!config->fltmgr_profile)
    {
        PRINT_DEBUG("[ROOTKITMON] No profile for fltmgr.sys was given!\n");
    }
    else
    {
        manual_hooks.push_back(register_profile_hook(drakvuf, config->fltmgr_profile, "fltmgr.sys", "FltRegisterFilter", flt_cb));
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, this->offsets))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to get kernel struct member offsets\n");
        throw -1;
    }

    drakvuf_enumerate_drivers(drakvuf, driver_visitor, static_cast<void*>(this));

    vmi_lock_guard vmi(drakvuf);

    // Hook HalPrivateDispatchTable on write
    if (!translate_ksym2p(vmi, "HalPrivateDispatchTable", &(this->halprivatetable)))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to translate symbol to physical address\n");
        throw -1;
    }
    manual_hooks.push_back(register_mem_hook(halprivatetable_overwrite_cb, this->halprivatetable, VMI_MEMACCESS_W));

    if (!drakvuf_get_kernel_struct_size(drakvuf, "_OBJECT_HEADER", &this->object_header_size))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to get _OBJECT_HEADER struct size\n");
        throw -1;
    }

    if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "ObTypeIndexTable", &this->type_idx_table))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to translate ObTypeIndexTable to VA\n");
        throw -1;
    }

    if (this->winver == VMI_OS_WINDOWS_10 && VMI_SUCCESS != vmi_read_8_ksym(vmi, "ObHeaderCookie", &this->ob_header_cookie))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to locate header cookie\n");
        throw -1;
    }

    if (!this->is32bit)
        for (const auto& drv_object : enumerate_driver_objects(vmi))
        {
            auto address = drv_object + offsets[DRIVER_OBJECT_STARTIO];
            // 28 Major functions + DriverUnload + DriverStartIo = 30 pointers
            driver_object_checksums[drv_object] = calc_checksum(vmi, address, this->guest_ptr_size * 30);
            // Enumerate all device_stacks of a particular driver
            driver_stacks[drv_object] = enumerate_driver_stacks(vmi, drv_object);
        }

    // Enumerate descriptors on all cores
    if (!enumerate_cores(vmi))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to enumerate descriptors\n");
        throw -1;
    }
    PRINT_DEBUG("[ROOTKITMON] Done init\n");
}

rootkitmon::~rootkitmon()
{
    delete[] offsets;
}

bool rootkitmon::stop_impl()
{
    if (!is_stopping() && !done_final_analysis)
    {
        PRINT_DEBUG("[ROOTKITMON] Injecting KiDeliverApc\n");
        // Hook dummy function so we could make final system analysis
        auto hook = createSyscallHook("KiDeliverApc", &rootkitmon::final_check_cb);
        if (!hook)
        {
            // Skip final analysis
            PRINT_DEBUG("[ROOTKITMON] Failed to hook KiDeliverApc\n");
            done_final_analysis = true;
            return pluginex::stop_impl();
        }
        this->syscall_hooks.push_back(std::move(hook));
        // Return status `Pending`
        return false;
    }
    if (done_final_analysis)
        return pluginex::stop_impl();
    // Return status `Pending`
    return false;
}
