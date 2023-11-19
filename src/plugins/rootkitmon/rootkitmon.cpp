/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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
#include <unordered_map>
#include <set>
#include "plugins/output_format.h"
#include "rootkitmon.h"
#include "private.h"

using namespace rootkitmon_ns;

static constexpr uint16_t vista_rtm_ver = 6000;
static constexpr uint16_t win7_sp1_ver = 7601;
static constexpr uint16_t win8_rtm_ver = 9200;

static inline size_t get_ci_table_size(vmi_instance_t vmi)
{
    // Table size is heavily dependent on build version but for win 8.1 and
    // higher we just assume table size is 30 elements long
    uint16_t ver = vmi_get_win_buildnumber(vmi);
    if (ver >= vista_rtm_ver && ver <= win7_sp1_ver)
        return 3;
    else if (ver >= win8_rtm_ver)
        return 30;
    return 0;
}

static inline void report(drakvuf_t drakvuf, const output_format_t format, const char* type, const char* action,
    const char* name = nullptr, const addr_t* value = nullptr, const addr_t* prev_value = nullptr,
    const char* module = nullptr)
{
    std::optional<fmt::Estr<const char*>> name_opt, module_opt;
    std::optional<fmt::Xval<addr_t>> value_opt, prev_value_opt;

    if (name)
    {
        name_opt = fmt::Estr(name);
    }
    if (value)
    {
        value_opt = fmt::Xval(*value);
    }
    if (prev_value)
    {
        prev_value_opt = fmt::Xval(*prev_value);
    }
    if (module)
    {
        module_opt = fmt::Estr(module);
    }

    fmt::print(format, "rootkitmon", drakvuf, nullptr,
        keyval("Type", fmt::Estr(type)),
        keyval("Action", fmt::Estr(action)),
        keyval("Name", name_opt),
        keyval("Value", value_opt),
        keyval("PreviousValue", prev_value_opt),
        keyval("Module", module_opt)
    );
}

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

static sha256_checksum_t& merge(sha256_checksum_t& s1, const sha256_checksum_t& s2)
{
    for (size_t i = 0; i < s1.size(); i++)
        s1[i] ^= s2[i];
    return s1;
}

/**
 * Enumerate PE sections with mem_execute and mem_not_paged flags.
 * Returns vector of <virtual address, aligned section size>
 */
static std::vector<std::pair<addr_t, size_t>> get_pe_sections(void* module, addr_t read_imagebase)
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
        if (section->characteristics & mem_not_paged && !(section->characteristics & mem_write))
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

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &ctx, num_pages, PROT_READ, access_ptrs.data()))
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
    report(drakvuf, plugin->format, "Function", "Called", "FwpmCalloutAdd0");
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
        report(drakvuf, plugin->format, "SystemStruct", "Modified", "HalPrivateDispatchTable");
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t check_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = GetTrapPlugin<rootkitmon>(info);
    plugin->check_ci(drakvuf, info);
    return VMI_EVENT_RESPONSE_NONE;
}

static void initialize_ci_checks(drakvuf_t drakvuf, rootkitmon* plugin, const rootkitmon_config* config)
{
    vmi_lock_guard vmi(drakvuf);

    plugin->ci_callbacks_va = 0;
    plugin->ci_enabled_va = 0;

    if (vmi_get_win_buildnumber(vmi) <= win8_rtm_ver)
    {
        if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "g_CiEnabled",   &plugin->ci_enabled_va) ||
            VMI_SUCCESS != vmi_translate_ksym2v(vmi, "g_CiCallbacks", &plugin->ci_callbacks_va))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to initialize g_CiEnabled or g_CiCallbacks\n");
            throw -1;
        }
    }
    else
    {
        // On win 8.1 and higher the `g_CiOptions` aka `g_CiEnabled` is located inside ci.dll module
        if (!config->ci_profile)
        {
            PRINT_DEBUG("[ROOTKITMON] No ci.dll profile\n");
            return;
        }
        // Extract g_CiOptions rva from json file
        auto profile_json = json_object_from_file(config->ci_profile);
        if (!profile_json)
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to load JSON debug info for ci.dll\n");
            throw -1;
        }
        addr_t ci_options_rva;
        if (!json_get_symbol_rva(drakvuf, profile_json, "g_CiOptions", &ci_options_rva))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to find g_CiOptions RVA in json for ci.dll\n");
            throw -1;
        }
        json_object_put(profile_json);

        addr_t list_head;
        if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
            throw -1;

        addr_t ci_module_base;
        if (!drakvuf_get_module_base_addr(drakvuf, list_head, "ci.dll", &ci_module_base))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to find ci.dll\n");
            throw -1;
        }
        plugin->ci_enabled_va = ci_module_base + ci_options_rva;
        if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "SeCiCallbacks", &plugin->ci_callbacks_va))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to find SeCiCallbacks\n");
            throw -1;
        }
    }
    // Fill initial values
    if (VMI_SUCCESS != vmi_read_8_va(vmi, plugin->ci_enabled_va, 4, &plugin->ci_enabled) )
        throw -1;
    plugin->ci_callbacks = calc_checksum(vmi, plugin->ci_callbacks_va, get_ci_table_size(vmi));

    plugin->syscall_hooks.push_back(plugin->createSyscallHook("SeValidateImageHeader", check_cb));
    plugin->syscall_hooks.push_back(plugin->createSyscallHook("SeValidateImageData", check_cb));
}

static void initialize_drv_checks(drakvuf_t drakvuf, rootkitmon* plugin)
{
    if (!plugin->is32bit)
    {
        drakvuf_enumerate_object_directory(drakvuf, [](drakvuf_t drakvuf, const object_info_t* info, void* ctx)
        {
            auto plugin = static_cast<rootkitmon*>(ctx);
            if (!strcmp((const char*)info->name->contents, "Driver"))
            {
                vmi_lock_guard vmi(drakvuf);
                // 28 Major functions + DriverUnload + DriverStartIo = 30 pointers
                auto drv_obj_crc = calc_checksum(vmi, info->base_addr + plugin->offsets[DRIVER_OBJECT_STARTIO], plugin->guest_ptr_size * 30);
                // Calculate FASTIO_DISPATCH array as well if present
                addr_t fastio_addr = 0;
                if (VMI_SUCCESS != vmi_read_addr_va(vmi, info->base_addr + plugin->offsets[DRIVER_OBJECT_FASTIODISPATCH], 0, &fastio_addr))
                {
                    PRINT_DEBUG("[ROOTKITMON] Failed to read DRIVER_OBJECT_FASTIODISPATCH pointer\n");
                    throw -1;
                }
                if (fastio_addr)
                    drv_obj_crc = merge(drv_obj_crc, calc_checksum(vmi, fastio_addr, plugin->fastio_size));
                plugin->driver_object_checksums[info->base_addr] = drv_obj_crc;
                // Enumerate all device_stacks of a particular driver
                plugin->driver_stacks[info->base_addr] = plugin->enumerate_driver_stacks(vmi, info->base_addr);
            }
        }, plugin);
    }
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
static bool driver_visitor(drakvuf_t drakvuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* ctx)
{
    auto plugin = static_cast<rootkitmon*>(ctx);
    vmi_lock_guard vmi(drakvuf);

    ACCESS_CONTEXT(a_ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
        .addr = module_info->base_addr
    );

    // Map 1 4KB page with PE header
    void* module = nullptr;
    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &a_ctx, 1, PROT_READ, &module) || !module )
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to map guest VA 0x%lx\n", a_ctx.addr);
        return true;
    }

    sha256_checksum_t driver_hash{ 0 };

    // Checksum every section and save it into `driver_sections_checksums`
    for (const auto& [virt_addr, virt_size] : get_pe_sections(module, module_info->base_addr))
    {
        auto aligned_size = align_by_page(virt_size);
        auto section_hash = calc_checksum(vmi, virt_addr, aligned_size);
        driver_hash       = merge(driver_hash, section_hash);
    }
    plugin->driver_sections_checksums[module_info->base_addr] = { std::move(driver_hash), (const char*)module_info->full_name->contents };
    munmap(module, VMI_PS_4KB);
    return true;
}

static std::string get_driver_name_by_addr(drakvuf_t drakvuf, addr_t addr)
{
    std::pair<std::string, addr_t> context{ "", addr };

    drakvuf_enumerate_drivers(drakvuf, [](drakvuf_t drakvuf, const module_info_t* info, bool*, bool* stop, void* ctx)
    {
        auto pass_context = reinterpret_cast<std::pair<std::string, addr_t>*>(ctx);
        if (pass_context->second >= info->base_addr && pass_context->second < info->base_addr + info->size)
        {
            pass_context->first.assign((const char*)info->full_name->contents);
            *stop = true;
        }
        return true;
    }, &context);
    return context.first;
}

void rootkitmon::check_driver_integrity(drakvuf_t drakvuf)
{
    auto past_drivers_checksums = std::move(this->driver_sections_checksums);
    this->driver_sections_checksums.clear();
    // Collect new checksums
    drakvuf_enumerate_drivers(drakvuf, driver_visitor, static_cast<void*>(this));
    // Compare
    for (const auto& [driver, data] : this->driver_sections_checksums)
    {
        const auto& [checksum, name] = data;
        // Find driver object
        if (past_drivers_checksums.find(driver) == past_drivers_checksums.end())
            continue;

        const auto& [p_checksum, p_name] = past_drivers_checksums[driver];
        if (checksum != p_checksum)
        {
            report(drakvuf, this->format, "DriverCRC", "Modified", nullptr, nullptr, nullptr, name.c_str());
        }
    }
}

void rootkitmon::check_driver_objects(drakvuf_t drakvuf)
{
    auto past_driver_object_checksums = std::move(this->driver_object_checksums);
    auto past_driver_stacks = std::move(this->driver_stacks);
    this->driver_object_checksums.clear();
    this->driver_stacks.clear();
    // Collect new info
    initialize_drv_checks(drakvuf, this);

    auto report_modification = [&](const char* type, addr_t driver_object)
    {
        vmi_lock_guard vmi(drakvuf);
        addr_t driver_base{};
        if (VMI_SUCCESS == vmi_read_addr_va(vmi, driver_object + this->offsets[DRIVER_OBJECT_DRIVERSTART], 0, &driver_base))
        {
            auto name = get_driver_name_by_addr(drakvuf, driver_base);
            report(drakvuf, this->format, type, "Modified", nullptr, nullptr, nullptr, name.c_str());
        }
    };

    // Compare dispatch table checksums
    for (const auto& [drv_object, checksum] : this->driver_object_checksums)
    {
        // Find driver object
        if (past_driver_object_checksums.find(drv_object) == past_driver_object_checksums.end())
            continue;

        const auto& p_checksum = past_driver_object_checksums[drv_object];

        if (checksum != p_checksum)
        {
            report_modification("DriverObject", drv_object);
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
                report_modification("DriverStack", drv_object);
            }

            for (size_t i = 0; i < dev_stack.size(); i++)
            {
                // Dev object hijack
                if (dev_stack[i] != p_dev_stack[i])
                {
                    report_modification("DriverStack", drv_object);
                    break;
                }
            }
        }
    }
}

void rootkitmon::check_descriptors(drakvuf_t drakvuf)
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
            report(drakvuf, this->format, "SystemRegister", "Modified", "IDTR", &desc_info.idtr_base, &t_desc_info.idtr_base);
            break;
        }
        if (desc_info.idt_checksum != t_desc_info.idt_checksum)
        {
            report(drakvuf, this->format, "SystemStruct", "Modified", "IDT");
            break;
        }
    }

    for (const auto& [vcpu, desc_info] : this->descriptors)
    {
        const auto& t_desc_info = past_descriptors[vcpu];
        if (desc_info.gdtr_base != t_desc_info.gdtr_base)
        {
            report(drakvuf, this->format, "SystemRegister", "Modified", "GDTR", &desc_info.gdtr_base, &t_desc_info.gdtr_base);
            break;
        }
        if (desc_info.gdt.size() != t_desc_info.gdt.size())
        {
            report(drakvuf, this->format, "SystemStruct", "Modified", "GDT");
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
                    report(drakvuf, this->format, "SystemStruct", "Modified", "GDT", &addr, &t_addr);
                    break;
                }
            }
        }
    }
}

void rootkitmon::check_ci(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_lock_guard vmi(drakvuf);

    if (!this->ci_enabled_va || !this->ci_callbacks_va)
        return;

    uint8_t ci_flag;
    if (VMI_SUCCESS != vmi_read_8_va(vmi, this->ci_enabled_va, 4, &ci_flag))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to read g_CiEnabled\n");
        return;
    }

    if (this->ci_enabled != ci_flag)
    {
        report(drakvuf, format, "SystemStruct", "Modified", "g_CiEnabled");
    }

    if (this->ci_callbacks != calc_checksum(vmi, this->ci_callbacks_va, get_ci_table_size(vmi)))
    {
        report(drakvuf, format, "SystemStruct", "Modified", "g_CiCallbacks");
    }
}

void rootkitmon::check_filter_callbacks(drakvuf_t drakvuf)
{
    if (!this->do_flt_checks)
        return;

    vmi_lock_guard vmi(drakvuf);

    auto old_callbacks = this->flt_callbacks;
    this->flt_callbacks.clear();

    enumerate_filter_callbacks(vmi);

    for (const auto& [volume, callbacks] : old_callbacks)
    {
        if (this->flt_callbacks.count(volume))
        {
            const auto& new_callbacks = this->flt_callbacks[volume];
            if (callbacks != new_callbacks)
            {
                report(drakvuf, format, "SystemStruct", "Modified", "VolumeFilterCallbacks");
            }
        }
    }
}

/**
 *  Callback to check if EFLAGS.SMAP were edited. If we've reached this point, MSR_LSTAR was changed and we've been redirected
 *  to custom syscall callback instead of default.
 */
event_response_t rootkitmon::rop_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    rootkitmon* plugin = static_cast<rootkitmon*>(info->trap->data);
    vmi_lock_guard vmi(drakvuf);
    uint64_t rflag;
    if (VMI_SUCCESS == vmi_get_vcpureg(vmi, &rflag, RFLAGS, info->vcpu))
    {

        if (rflag & ac_smap_mask)
        {
            report(drakvuf, plugin->format, "SecurityFeature", "Disabled", "EFLAGS.SMAP");
        }
        // Release memory hook. If EFLAGS.SMAP wasn't set at this point, we don't need this bp anymore
        plugin->rop_hooks.erase(info->trap->breakpoint.addr);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 *  Callback to check if MSR_LSTAR were edited to redirect syscall to a custom user-defined callback,
 *  it's the first point before setting FLAGS.SMAP(AC) to disable SMAP technology before syscall
 */
event_response_t rootkitmon::msr_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    rootkitmon* plugin = static_cast<rootkitmon*>(info->trap->data);

    PRINT_DEBUG("[ROOTKITMON] LSTAR: %lx -> %lx\n", plugin->msr_lstar[info->vcpu], info->reg->value);
    if (plugin->msr_lstar[info->vcpu] == info->reg->value)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    {
        // PatchGuard changes LSTAR inside FsRtlMdlReadCompleteDevEx:
        // [...]
        // 41 BE 82 00 00 C0    mov     r14d, 0C0000082h
        // 41 8B CE             mov     ecx, r14d
        // 0F 32                rdmsr
        // 48 C1 E2 20          shl     rdx, 20h
        // 48 0B C2             or      rax, rdx
        // 48 8D 96 7A 08 00 00 lea     rdx, [rsi+87Ah]
        // 48 8B D8             mov     rbx, rax
        // 48 8B C2             mov     rax, rdx
        // 48 C1 EA 20          shr     rdx, 20h
        // 0F 30                wrmsr
        // [...]
        auto vmi = vmi_lock_guard(drakvuf);

        uint8_t instr{};
        if (VMI_SUCCESS == vmi_read_va(vmi, info->reg->value, 4, sizeof(instr), (void*)&instr, nullptr) && instr == 0xc3) // ret (C3)
        {
            PRINT_DEBUG("[ROOTKITMON] LSTAR: Skip modification by PatchGuard\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    auto name = get_driver_name_by_addr(drakvuf, info->reg->value);
    report(drakvuf, plugin->format, "SystemRegister", "Modified", "LSTAR", &info->reg->value, &plugin->msr_lstar[info->vcpu], name.empty() ? nullptr : name.c_str());

    auto trap = new drakvuf_trap_t
    {
        .type = BREAKPOINT,
        .breakpoint.lookup_type = LOOKUP_PID,
        .breakpoint.pid = info->proc_data.pid,
        .breakpoint.addr_type = ADDR_VA,
        .breakpoint.addr = (addr_t)info->reg->value,
        .data = (void*)plugin,
        .cb = rootkitmon::rop_callback,
    };
    plugin->rop_hooks[info->reg->value] = plugin->createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t rootkitmon::cr4_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    rootkitmon* plugin = static_cast<rootkitmon*>(info->trap->data);

    PRINT_DEBUG("[ROOTKITMON] CR4: %lx -> %lx\n", info->reg->previous, info->reg->value);
    if (VMI_GET_BIT(info->reg->previous, cr4_smep_mask_bitoffset) == 1 && VMI_GET_BIT(info->reg->value, cr4_smep_mask_bitoffset) == 0)
    {
        report(drakvuf, plugin->format, "SecurityFeature", "Disabled", "CR4.SMEP");
    }

    if (VMI_GET_BIT(info->reg->previous, cr4_smap_mask_bitoffset) == 1 && VMI_GET_BIT(info->reg->value, cr4_smap_mask_bitoffset) == 0)
    {
        report(drakvuf, plugin->format, "SecurityFeature", "Disabled", "CR4.SMAP");
    }

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

void rootkitmon::enumerate_filter_callbacks(vmi_instance_t vmi)
{
    if (is32bit)
        return;

    auto walk_list = [&](addr_t head, auto cb)
    {
        addr_t entry{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, head, 0, &entry))
            return;

        while (entry && entry != head)
        {
            cb(entry);
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
                break;
        }
    };

    addr_t frame_list_head = this->flt_globals_va + this->flt_offsets[FLT_GLOBALS_FRAMELIST] + this->flt_offsets[FLT_RESOURCE_LIST_HEAD_RLIST];

    walk_list(frame_list_head, [&](addr_t frame)
    {
        // 0: kd> dt _FLTP_FRAME
        // FLTMGR!_FLTP_FRAME
        //    +0x000 Type             : _FLT_TYPE
        //    +0x008 Links            : _LIST_ENTRY
        addr_t volume_list_head = frame - 8 + this->flt_offsets[FLTP_FRAME_ATTACHEDVOLUMES] + this->flt_offsets[FLT_RESOURCE_LIST_HEAD_RLIST];
        walk_list(volume_list_head, [&](addr_t volume)
        {
            // 0: kd> dt _FLT_OBJECT
            // FLTMGR!_FLT_OBJECT
            //    +0x000 Flags            : _FLT_OBJECT_FLAGS
            //    +0x004 PointerCount     : Uint4B
            //    +0x008 RundownRef       : _EX_RUNDOWN_REF
            //    +0x010 PrimaryLink      : _LIST_ENTRY
            this->flt_callbacks[volume - 0x10] = {};
            // 0: kd> dt _CALLBACK_CTRL
            // FLTMGR!_CALLBACK_CTRL
            //    +0x000 OperationLists   : [50] _LIST_ENTRY
            for (int i = 0; i < 50; i++)
            {
                addr_t cb_list_head = volume - 0x10 + this->flt_offsets[FLT_VOLUME_CALLBACKS] + this->flt_offsets[FLT_CALLBACK_CTRL_LISTS] + i * this->guest_ptr_size * 2;
                walk_list(cb_list_head, [&](addr_t cb_node)
                {
                    addr_t pre{}, post{};
                    if (VMI_SUCCESS != vmi_read_addr_va(vmi, cb_node + this->flt_offsets[CALLBACKNODE_PREOPERATION], 0, &pre) ||
                        VMI_SUCCESS != vmi_read_addr_va(vmi, cb_node + this->flt_offsets[CALLBACKNODE_POSTOPERATION], 0, &post))
                    {
                        return;
                    }
                    this->flt_callbacks[volume - 0x10][i].push_back({ pre, post });
                });
            }
        });
    });
}

rootkitmon::rootkitmon(drakvuf_t drakvuf, const rootkitmon_config* config, output_format_t output)
    : pluginex(drakvuf, output), format(output)
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
        if (!vmi_get_windows_build_info(vmi, &build_info))
            throw -1;

        this->winver = build_info.version;
    }

    initialize_ci_checks(drakvuf, this, config);

    if (!config->fwpkclnt_profile)
        PRINT_DEBUG("[ROOTKITMON] No profile for fwpkclnt.sys was given!\n");
    else
        manual_hooks.push_back(register_profile_hook(drakvuf, config->fwpkclnt_profile, "fwpkclnt.sys", "FwpmCalloutAdd0", wfp_cb));

    if (!config->fltmgr_profile)
    {
        PRINT_DEBUG("[ROOTKITMON] No profile for fltmgr.sys was given!\n");
        this->do_flt_checks = false;
    }
    else
    {
        auto profile_json = json_object_from_file(config->fltmgr_profile);
        if (!profile_json)
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to load JSON debug info for fltmgr.sys\n");
            throw -1;
        }
        if (!json_get_symbol_rva(drakvuf, profile_json, "FltGlobals", &this->flt_globals_va))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to find FltGlobals RVA in json for fltmgr.sys\n");
            throw -1;
        }

        if (!json_get_struct_members_array_rva(drakvuf, profile_json, flt_offset_names, __FLT_OFFSET_MAX, flt_offsets.data()))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to resolve flt offsets\n");
            throw -1;
        }
        json_object_put(profile_json);

        vmi_lock_guard vmi(drakvuf);
        addr_t list_head{};
        if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to read PsLoadedModuleList\n");
            throw -1;
        }

        addr_t fltmgr_base{};
        if (!drakvuf_get_module_base_addr(drakvuf, list_head, "fltmgr.sys", &fltmgr_base))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to resolve fltmgr.sys\n");
            throw -1;
        }
        this->flt_globals_va += fltmgr_base;

        enumerate_filter_callbacks(vmi);

        this->do_flt_checks = true;
    }

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[ROOTKITMON] Failed to get kernel struct member offsets\n");
        throw -1;
    }

    drakvuf_enumerate_drivers(drakvuf, driver_visitor, static_cast<void*>(this));

    {
        vmi_lock_guard vmi(drakvuf);

        // Hook HalPrivateDispatchTable on write
        if (!translate_ksym2p(vmi, "HalPrivateDispatchTable", &(this->halprivatetable)))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to translate symbol to physical address\n");
            throw -1;
        }
        manual_hooks.push_back(register_mem_hook(halprivatetable_overwrite_cb, this->halprivatetable, VMI_MEMACCESS_W));

        if (!drakvuf_get_kernel_struct_size(drakvuf, "_FAST_IO_DISPATCH", &this->fastio_size))
        {
            throw -1;
        }

        // Enumerate descriptors on all cores
        if (!enumerate_cores(vmi))
        {
            PRINT_DEBUG("[ROOTKITMON] Failed to enumerate descriptors\n");
            throw -1;
        }
    }

    initialize_drv_checks(drakvuf, this);
    // MSR hook
    auto trap = new drakvuf_trap_t();
    trap->type = REGISTER;
    trap->regaccess.type = MSR_ANY;
    trap->regaccess.msr = msr_lstar_index;
    trap->data = (void*)this;
    trap->ah_cb = nullptr;
    trap->cb = &rootkitmon::msr_callback;
    this->msr_hook = createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });

    // cr4 hook
    auto cr4_trap = new drakvuf_trap_t();
    cr4_trap->type = REGISTER;
    cr4_trap->regaccess.type = CR4;
    cr4_trap->data = (void*)this;
    cr4_trap->ah_cb = nullptr;
    cr4_trap->cb = &rootkitmon::cr4_callback;
    this->cr4_hook = createManualHook(cr4_trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });
}

bool rootkitmon::stop_impl()
{
    check_driver_integrity(drakvuf);
    check_driver_objects(drakvuf);
    check_descriptors(drakvuf);
    check_ci(drakvuf, nullptr);
    check_filter_callbacks(drakvuf);
    return pluginex::stop_impl();
}
