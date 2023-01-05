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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <err.h>

#include "plugins/plugins.h"
#include "plugins/plugins_ex.h"
#include "plugins/output_format.h"

#include "private.h"
#include "ssdtmon.h"

static std::array<uint8_t, 32> ssdtmon_sha256_calc(vmi_instance_t vmi, addr_t addr, size_t size)
{
    std::array<uint8_t, 32> out{ 0 };

    addr_t aligned_size = size & ~(VMI_PS_4KB - 1);
    if (size & (VMI_PS_4KB - 1))
        aligned_size += VMI_PS_4KB;

    auto intra_page_offset = addr & (VMI_PS_4KB - 1);
    auto num_pages = aligned_size / VMI_PS_4KB;

    std::vector<void*> access_ptrs(num_pages, nullptr);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
        .addr = addr
    );

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &ctx, num_pages, access_ptrs.data()))
        return out;

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
        throw -1;

    g_checksum_free(checksum);
    return out;
}

event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    ssdtmon* s = (ssdtmon*)info->trap->data;

    if ( info->trap_pa > s->kiservicetable - 8 && info->trap_pa <= s->kiservicetable + sizeof(uint32_t) * s->kiservicelimit + sizeof(uint32_t) - 1 )
    {
        int64_t table_index = (info->trap_pa - s->kiservicetable) / sizeof(uint32_t);
        fmt::print(s->format, "ssdtmon", drakvuf, info,
            keyval("TableIndex", fmt::Nval(table_index)),
            keyval("Table", fmt::Qstr("SSDT"))
        );
    }
    for (size_t i = 0; i < s->w32p_ssdt.size(); i++)
    {
        const auto& [base, size] = s->w32p_ssdt[i];
        if (info->trap_pa >= base && info->trap_pa < base + size)
        {
            int64_t table_index = (info->trap_pa - base + i * VMI_PS_4KB) / sizeof(uint32_t);
            fmt::print(s->format, "ssdtmon", drakvuf, info,
                keyval("TableIndex", fmt::Nval(table_index)),
                keyval("Table", fmt::Qstr("SSDTShadow"))
            );
        }
    }
    return 0;
}

static bool get_driver_base(drakvuf_t drakvuf, ssdtmon* plugin, const char* driver_name, addr_t* base)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4
    );

    vmi_lock_guard vmi(drakvuf);

    addr_t list_head = 0;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
    {
        PRINT_DEBUG("[SSDTMON] Failed to read PsLoadedModuleList value\n");
        return false;
    }

    list_head -= plugin->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS];

    addr_t entry = list_head;
    do
    {
        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS] + plugin->offsets[LIST_ENTRY_FLINK];
        if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &entry))
        {
            PRINT_DEBUG("[SSDTMON] Failed to read next entry (VA 0x%lx)\n", ctx.addr);
            return false;
        }

        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_FULLDLLNAME];
        auto name = drakvuf_read_unicode_common(drakvuf, &ctx);
        if (name && name->contents)
        {
            auto drvname = std::string(reinterpret_cast<char*>(name->contents));
            vmi_free_unicode_str(name);
            if (drvname.find(driver_name) != std::string::npos)
            {
                ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
                if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, base))
                    return false;
                return true;
            }

        }
    } while (entry != list_head);

    return false;
}

std::unique_ptr<libhook::ManualHook> ssdtmon::register_mem_hook(hook_cb_t callback, addr_t pa)
{
    auto trap = new drakvuf_trap_t
    {
        .type = MEMACCESS,
        .memaccess.gfn = pa >> 12,
            .memaccess.type = PRE,
            .memaccess.access = VMI_MEMACCESS_W,
            .data = (void*)this,
            .name = nullptr,
            .ttl = UNLIMITED_TTL,
            .ah_cb = nullptr,
            .cb = callback,
    };

    auto hook = createManualHook(trap, [](drakvuf_trap_t* trap_)
    {
        delete trap_;
    });
    if (!hook)
    {
        PRINT_DEBUG("[SSDTMON] Failed to hook 0x%lx\n", pa >> 12);
        throw -1;
    }

    return hook;
}

/* ----------------------------------------------------- */

ssdtmon::ssdtmon(drakvuf_t drakvuf, const ssdtmon_config* config, output_format_t output)
    : pluginex(drakvuf, output), format{output}, offsets(new size_t[__OFFSET_MAX])
{
    addr_t kiservicetable_rva = 0;
    addr_t kiservicelimit_rva = 0;
    addr_t kernbase = 0;

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, this->offsets))
    {
        PRINT_DEBUG("[SSDTMON] Failed to get kernel struct member offsets\n");
        throw -1;
    }

    if (config->win32k_profile)
    {
        addr_t gui_process = 0;
        if (!drakvuf_find_process(drakvuf, ~0, "explorer.exe", &gui_process))
        {
            PRINT_DEBUG("[SSDTMON] Failed to find EPROCESS of \"explorer.exe\"\n");
            throw -1;
        }

        vmi_pid_t gui_pid = 0;
        if (!drakvuf_get_process_pid(drakvuf, gui_process, &gui_pid))
        {
            PRINT_DEBUG("[SSDTMON] Failed to get PID of \"explorer.exe\"\n");
            throw -1;
        }

        json_object* profile_json = json_object_from_file(config->win32k_profile);
        if (!profile_json)
        {
            PRINT_DEBUG("[SSDTMOD] Failed to load JSON debug info for win32k.sys\n");
            throw -1;
        }

        addr_t w32pst_rva = 0;
        if (!json_get_symbol_rva(drakvuf, profile_json, "W32pServiceTable", &w32pst_rva))
        {
            PRINT_DEBUG("[SSDTMON] Failed to get RVA of win32k!W32pServiceTable\n");
            throw -1;
        }

        addr_t w32psl_rva = 0;
        if (!json_get_symbol_rva(drakvuf, profile_json, "W32pServiceLimit", &w32psl_rva))
        {
            PRINT_DEBUG("[SSDTMON] Failed to get RVA of win32k!W32pServiceLimit\n");
            throw -1;
        }

        {
            addr_t w32k_base = 0;
            // Locate Win32k.sys base address
            if (!get_driver_base(drakvuf, this, "win32k.sys", &w32k_base))
            {
                PRINT_DEBUG("[SSDTMON] Failed to find win32k.sys in PsLoadedModuleList\n");
                throw -1;
            }
            // Read ssdt shadow size
            vmi_lock_guard vmi(drakvuf);
            uint32_t w32pservicelimit;
            if (VMI_SUCCESS != vmi_read_32_va(vmi, w32k_base + w32psl_rva, gui_pid, &w32pservicelimit))
            {
                PRINT_DEBUG("[SSDTMON] Failed to read W32pServiceLimit\n");
                throw -1;
            }

            size_t servicetable_len = sizeof(uint32_t) * w32pservicelimit;
            size_t n_pages = (servicetable_len + VMI_PS_4KB) / VMI_PS_4KB;

            for (size_t page = 0; page != n_pages; ++page)
            {
                // NOTE: We use vmi_translate_uv2p instead of vmi_translate_kv2p because Win32k.sys mapping is not present
                // in system process, only in process with GUI dependencies, hence we use explorer.exe as a pid.
                addr_t page_addr = w32k_base + w32pst_rva + page * VMI_PS_4KB;
                size_t page_payload_len = std::min<size_t>(servicetable_len - page * VMI_PS_4KB, VMI_PS_4KB);

                addr_t page_paddr;
                if (VMI_SUCCESS != vmi_translate_uv2p(vmi, page_addr, gui_pid, &page_paddr))
                {
                    PRINT_DEBUG("[SSDTMON] Failed to translate page %zu of win32k!W32pServiceTable to physical address\n", page);
                    throw -1;
                }

                this->ssdt_traps.push_back(register_mem_hook(write_cb, page_paddr));
                this->w32p_ssdt.emplace_back(page_paddr, page_payload_len);

                if (page == 0)
                {
                    PRINT_DEBUG("[SSDTMON] SSDT shadow is at 0x%lx. Number of syscalls: %u. Size: %zu\n",
                        page_paddr, w32pservicelimit, servicetable_len);
                }
            }
        }
        json_object_put(profile_json);
    }

    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiServiceTable", &kiservicetable_rva) )
    {
        PRINT_DEBUG("SSDT plugin can't find KiServiceTable RVA\n");
        throw -1;
    }
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "KiServiceLimit", &kiservicelimit_rva) )
    {
        PRINT_DEBUG("SSDT plugin can't find KiServiceLimit RVA\n");
        throw -1;
    }

    kernbase = drakvuf_get_kernel_base(drakvuf);
    if ( !kernbase )
    {
        PRINT_DEBUG("SSDT plugin can't find kernel base address\n");
        throw -1;
    }

    vmi_lock_guard vmi(drakvuf);
    if ( VMI_FAILURE == vmi_translate_kv2p(vmi, kernbase + kiservicetable_rva, &this->kiservicetable) )
        throw -1;

    vmi_read_32_va(vmi, kernbase + kiservicelimit_rva, 0, &this->kiservicelimit);

    if ( !this->kiservicetable )
    {
        PRINT_DEBUG("SSDT plugin can't find the physical address of KiServiceTable\n");
        throw -1;
    }
    if ( !this->kiservicelimit )
    {
        PRINT_DEBUG("SSDT plugin can't read the value of KiServiceLimit\n");
        throw -1;
    }

    PRINT_DEBUG("SSDT is at 0x%lx. Number of syscalls: %u. Size: %lu\n",
        this->kiservicetable,
        this->kiservicelimit,
        sizeof(uint32_t)*this->kiservicelimit);

    this->ssdt_traps.push_back(register_mem_hook(write_cb, kiservicetable));

    addr_t sdt_rva, sdt_shadow_rva;

    if (!drakvuf_get_kernel_symbol_rva(drakvuf, "KeServiceDescriptorTable", &sdt_rva) ||
        !drakvuf_get_kernel_symbol_rva(drakvuf, "KeServiceDescriptorTableShadow", &sdt_shadow_rva))
    {
        PRINT_DEBUG("[SSDTMON] Failed to get RVA of nt!KeServiceDescriptorTableShadow or nt!KeServiceDescriptorTable\n");
        throw -1;
    }

    this->sdt_va = drakvuf_get_kernel_base(drakvuf) + sdt_rva;
    this->sdt_shadow_va = drakvuf_get_kernel_base(drakvuf) + sdt_shadow_rva;

    bool is64 = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E);
    // SDT - 4 pointers long
    this->sdt_crc = ssdtmon_sha256_calc(vmi, this->sdt_va, is64 ? 32 : 16);
    // SDT shadow - 8 pointers long
    this->sdt_shadow_crc = ssdtmon_sha256_calc(vmi, this->sdt_shadow_va, is64 ? 64 : 32);
}

bool ssdtmon::stop_impl()
{
    if (!is_stopping())
    {
        bool is64 = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E);
        vmi_lock_guard vmi(drakvuf);
        if (sdt_crc != ssdtmon_sha256_calc(vmi, sdt_va, is64 ? 32 : 16))
        {
            fmt::print(format, "ssdtmon", drakvuf, nullptr, keyval("Table", fmt::Qstr("SDT")));
        }
        if (sdt_shadow_crc != ssdtmon_sha256_calc(vmi, sdt_shadow_va, is64 ? 64 : 32))
        {
            fmt::print(format, "ssdtmon", drakvuf, nullptr, keyval("Table", fmt::Qstr("SDTShadow")));
        }
    }
    return pluginex::stop_impl();
}

ssdtmon::~ssdtmon()
{
    delete[] offsets;
}
