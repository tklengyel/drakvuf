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
#include <json-c/json.h>
#include "../xen_helper/xen_helper.h"

#include "libdrakvuf.h"
#include "private.h"
#include "json-profile.h"

#ifdef DRAKVUF_DEBUG
bool verbose = 0;
#endif


uint64_t drakvuf_get_limited_traps_ttl(drakvuf_t drakvuf)
{
    return drakvuf->limited_traps_ttl;
}

void drakvuf_close(drakvuf_t drakvuf, const bool pause)
{
    if (!drakvuf)
        return;

    if (drakvuf->vmi)
        close_vmi(drakvuf);

    g_free(drakvuf->event_fds);
    g_free(drakvuf->fd_info_lookup);
    GSList* loop = drakvuf->event_fd_info;
    while (loop)
    {
        g_free(loop->data);
        loop = loop->next;
    }
    g_slist_free(drakvuf->event_fd_info);

    if (drakvuf->xen)
    {
        if ( !pause )
            drakvuf_force_resume(drakvuf);

        xen_free_interface(drakvuf->xen);
    }

    if (drakvuf->json_wow)
    {
        json_object_put(drakvuf->json_wow);
        drakvuf->json_wow = NULL;
    }

    g_free(drakvuf->offsets);
    g_free(drakvuf->bitfields);
    g_free(drakvuf->sizes);
    g_mutex_clear(&drakvuf->vmi_lock);
    g_free(drakvuf->dom_name);
    g_free(drakvuf->json_kernel_path);
    g_free(drakvuf->json_wow_path);
    g_free(drakvuf);
}

bool drakvuf_init(drakvuf_t* drakvuf, const char* domain, const char* json_kernel_path, const char* json_wow_path, bool _verbose, bool libvmi_conf, addr_t kpgd, bool fast_singlestep, uint64_t limited_traps_ttl)
{

    if ( !domain || !json_kernel_path )
        return 0;

#ifdef DRAKVUF_DEBUG
    verbose = _verbose;
#endif

    *drakvuf = (drakvuf_t)g_try_malloc0(sizeof(struct drakvuf));

    (*drakvuf)->limited_traps_ttl = limited_traps_ttl;

    (*drakvuf)->json_kernel_path = g_strdup(json_kernel_path);

    if ( json_wow_path )
    {
        (*drakvuf)->json_wow = json_object_from_file(json_wow_path);
        (*drakvuf)->json_wow_path = g_strdup(json_wow_path);
    }
    else
        PRINT_DEBUG("drakvuf_init: Rekall WoW64 profile not used\n");

    (*drakvuf)->kpgd = kpgd;

    g_mutex_init(&(*drakvuf)->vmi_lock);

    if ( !xen_init_interface(&(*drakvuf)->xen) )
        goto err;

    /* register the main VMI event callback */
    drakvuf_event_fd_add(*drakvuf, (*drakvuf)->xen->evtchn_fd, drakvuf_vmi_event_callback, drakvuf);
    PRINT_DEBUG("drakvuf_init: adding event_fd done\n");

    get_dom_info((*drakvuf)->xen, domain, &(*drakvuf)->domID, &(*drakvuf)->dom_name);
    domid_t test = ~0;
    if ( (*drakvuf)->domID == test )
        goto err;

    drakvuf_pause(*drakvuf);

    if (!init_vmi(*drakvuf, libvmi_conf, fast_singlestep))
        goto err;

    switch ((*drakvuf)->os)
    {
        case VMI_OS_WINDOWS:
            if ( !set_os_windows(*drakvuf) )
                goto err;
            break;
        case VMI_OS_LINUX:
            if ( !set_os_linux(*drakvuf) )
                goto err;
            break;
        case VMI_OS_UNKNOWN: /* fall-through */
        case VMI_OS_FREEBSD: /* fall-through */
        default:
            fprintf(stderr, "The Rekall profile describes an unknown operating system kernel!\n");
            goto err;
    }

    PRINT_DEBUG("libdrakvuf initialized\n");

    return 1;

err:
    drakvuf_close(*drakvuf, 1);
    *drakvuf = NULL;

    PRINT_DEBUG("libdrakvuf initialization failed\n");

    return 0;
}

void drakvuf_interrupt(drakvuf_t drakvuf, int sig)
{
    drakvuf->interrupted = sig;
}

int drakvuf_is_interrupted(drakvuf_t drakvuf)
{
    return drakvuf->interrupted;
}

bool inject_trap_breakpoint(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    if (trap->breakpoint.lookup_type == LOOKUP_NONE)
    {
        return inject_trap_pa(drakvuf, trap, trap->breakpoint.addr);
    }

    if (trap->breakpoint.lookup_type == LOOKUP_PID || trap->breakpoint.lookup_type == LOOKUP_NAME)
    {
        if (trap->breakpoint.addr_type == ADDR_RVA && trap->breakpoint.module)
        {

            vmi_pid_t pid = -1;
            const char* name = NULL;
            addr_t module_list = 0;

            if (trap->breakpoint.pid == 4 || !strcmp(trap->breakpoint.proc, "System"))
            {

                pid = 4;
                if (VMI_FAILURE == vmi_read_addr_ksym(drakvuf->vmi, "PsLoadedModuleList", &module_list))
                    return 0;

            }
            else
            {

                /* Process library */
                addr_t process_base;

                if (trap->breakpoint.lookup_type == LOOKUP_PID)
                    pid = trap->breakpoint.pid;
                if (trap->breakpoint.lookup_type == LOOKUP_NAME)
                    name = trap->breakpoint.proc;

                if ( !drakvuf_find_process(drakvuf, pid, name, &process_base) )
                    return 0;

                if ( pid == -1 && !drakvuf_get_process_pid(drakvuf, process_base, &pid) )
                    return 0;

                if ( !drakvuf_get_module_list(drakvuf, process_base, &module_list) )
                    return 0;
            }

            return inject_traps_modules(drakvuf, trap, module_list, pid);
        }

        if (trap->breakpoint.addr_type == ADDR_VA)
        {
            addr_t dtb;
            addr_t trap_pa;
            if ( VMI_FAILURE == vmi_pid_to_dtb(drakvuf->vmi, trap->breakpoint.pid, &dtb) )
            {
                PRINT_DEBUG("No DTB found for pid %i\n", trap->breakpoint.pid);
                return 0;
            }

            if ( VMI_FAILURE == vmi_pagetable_lookup(drakvuf->vmi, dtb, trap->breakpoint.addr, &trap_pa) )
            {
                PRINT_DEBUG("Failed to find PA for breakpoint VA addr 0x%lx in DTB 0x%lx\n", trap->breakpoint.addr, dtb);
                return 0;
            }

            return inject_trap_pa(drakvuf, trap, trap_pa);
        }

        if (trap->breakpoint.addr_type == ADDR_PA)
        {
            fprintf(stderr, "DRAKVUF Trap misconfiguration: PID lookup specified for PA location\n");
            return 0;
        }
    }

    if (trap->breakpoint.lookup_type == LOOKUP_DTB)
    {
        if (trap->breakpoint.addr_type == ADDR_VA)
        {
            addr_t trap_pa;
            if ( VMI_FAILURE == vmi_pagetable_lookup(drakvuf->vmi, trap->breakpoint.dtb, trap->breakpoint.addr, &trap_pa) )
                return 0;

            PRINT_DEBUG("Breakpoint VA 0x%" PRIx64" -> PA 0x%" PRIx64 "\n", trap->breakpoint.addr, trap_pa);

            return inject_trap_pa(drakvuf, trap, trap_pa);
        }

        //TODO: ADDR_RVA
    }

    return 0;
}

bool inject_trap_reg(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    if (CR3 == trap->reg)
    {
        if ( !drakvuf->cr3 && !control_cr3_trap(drakvuf, 1) )
            return 0;

        drakvuf->cr3 = g_slist_prepend(drakvuf->cr3, trap);
        return 1;
    }

    fprintf(stderr, "Support for trapping requested register is not (yet) implemented!\n");

    return 0;
}

bool inject_trap_catchall_breakpoint(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    drakvuf->catchall_breakpoint = g_slist_prepend(drakvuf->catchall_breakpoint, trap);
    return 1;
};

bool inject_trap_debug(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    if ( !drakvuf->debug && !control_debug_trap(drakvuf, 1) )
        return 0;

    drakvuf->debug = g_slist_prepend(drakvuf->debug, trap);
    return 1;
};

bool inject_trap_cpuid(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    if ( !drakvuf->cpuid && !control_cpuid_trap(drakvuf, 1) )
        return 0;

    drakvuf->cpuid = g_slist_prepend(drakvuf->cpuid, trap);
    return 1;
};

bool drakvuf_add_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    bool ret;

    if (!trap || !trap->cb)
        return 0;

    if (!trap->ah_cb)
        trap->ah_cb = drakvuf_unhook_trap;

    if (g_hash_table_lookup(drakvuf->remove_traps, &trap))
    {
        g_hash_table_remove(drakvuf->remove_traps, &trap);
        return 1;
    }

    drakvuf_pause(drakvuf);

    switch (trap->type)
    {
        case BREAKPOINT:
            ret = inject_trap_breakpoint(drakvuf, trap);
            break;
        case MEMACCESS:
            ret = inject_trap_mem(drakvuf, trap, 0);
            break;
        case REGISTER:
            ret = inject_trap_reg(drakvuf, trap);
            break;
        case DEBUG:
            ret = inject_trap_debug(drakvuf, trap);
            break;
        case CPUID:
            ret = inject_trap_cpuid(drakvuf, trap);
            break;
        case CATCHALL_BREAKPOINT:
            ret = inject_trap_catchall_breakpoint(drakvuf, trap);
            break;
        case __INVALID_TRAP_TYPE: /* fall-through */
        default:
            ret = 0;
            break;
    }

    drakvuf_resume(drakvuf);
    return ret;
}

void drakvuf_remove_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap,
                         drakvuf_trap_free_t free_routine)
{
    if ( drakvuf->in_callback)
    {
        struct free_trap_wrapper* free_wrapper = (struct free_trap_wrapper*)g_hash_table_lookup(drakvuf->remove_traps, &trap);

        if (!free_wrapper)
        {
            free_wrapper = (struct free_trap_wrapper*)g_slice_alloc0(sizeof(struct free_trap_wrapper));
            free_wrapper->free_routine = free_routine;
            free_wrapper->trap = trap;
            g_hash_table_insert(drakvuf->remove_traps,
                                g_memdup(&trap, sizeof(void*)),
                                free_wrapper);
        }

        free_wrapper->counter++;
    }
    else
    {
        remove_trap(drakvuf, trap);
        if (free_routine)
            free_routine(trap);
    }
}

void drakvuf_unhook_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap)
{
    drakvuf_remove_trap(drakvuf, trap, NULL);
}

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf)
{
    g_mutex_lock(&drakvuf->vmi_lock);
    return drakvuf->vmi;
}

void drakvuf_release_vmi(drakvuf_t drakvuf)
{
    g_mutex_unlock(&drakvuf->vmi_lock);
}

void drakvuf_pause (drakvuf_t drakvuf)
{
    xen_pause(drakvuf->xen, drakvuf->domID);
}

void drakvuf_resume (drakvuf_t drakvuf)
{
    xen_resume(drakvuf->xen, drakvuf->domID);
}

void drakvuf_force_resume (drakvuf_t drakvuf)
{
    xen_force_resume(drakvuf->xen, drakvuf->domID);
}

bool json_get_struct_members_array_rva(
    drakvuf_t drakvuf,
    json_object* json,
    const char* struct_name_symbol_array[][2],
    addr_t array_size,
    addr_t* rva)
{
    return json_lookup_array(
               drakvuf,
               json,
               struct_name_symbol_array,
               array_size,
               rva,
               NULL);
}

const char* drakvuf_get_json_wow_path(drakvuf_t drakvuf)
{
    return drakvuf->json_wow_path;
}

json_object* drakvuf_get_json_wow(drakvuf_t drakvuf)
{
    return drakvuf->json_wow;
}

addr_t drakvuf_get_kernel_base(drakvuf_t drakvuf)
{
    return drakvuf->kernbase;
}

os_t drakvuf_get_os_type(drakvuf_t drakvuf)
{
    return drakvuf->os;
}

page_mode_t drakvuf_get_page_mode(drakvuf_t drakvuf)
{
    return drakvuf->pm;
}

int drakvuf_get_address_width(drakvuf_t drakvuf)
{
    return drakvuf->address_width;
}

bool drakvuf_get_current_process_data(drakvuf_t drakvuf, drakvuf_trap_info_t* info, proc_data_priv_t* proc_data)
{
    addr_t process_base = drakvuf_get_current_process(drakvuf, info);
    // TODO - Windows version of get process tid needed.
    return drakvuf_get_process_data_priv(drakvuf, process_base, proc_data) && drakvuf_get_current_thread_id(drakvuf, info, (uint32_t*)&proc_data->tid);
}

bool drakvuf_get_process_data(drakvuf_t drakvuf, addr_t process_base, proc_data_t* proc_data)
{
    proc_data_priv_t proc_data_priv = { 0 };
    bool success = drakvuf_get_process_data_priv(drakvuf, process_base, &proc_data_priv);
    proc_data->name = proc_data_priv.name;
    proc_data->pid = proc_data_priv.pid;
    proc_data->ppid = proc_data_priv.ppid;
    proc_data->base_addr = proc_data_priv.base_addr;
    proc_data->userid = proc_data_priv.userid;
    proc_data->tid = proc_data_priv.tid;
    return success;
}

char* drakvuf_read_ascii_str(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    return vmi_read_str(drakvuf->vmi, &ctx);
}

unicode_string_t* drakvuf_read_unicode_common(vmi_instance_t vmi, const access_context_t* ctx)
{
    unicode_string_t* us = vmi_read_unicode_str(vmi, ctx);
    if ( !us )
        return NULL;

    unicode_string_t* out = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));

    if ( !out )
    {
        vmi_free_unicode_str(us);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(us, out, "UTF-8");
    vmi_free_unicode_str(us);

    if (VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

unicode_string_t* drakvuf_read_unicode(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    if ( !addr )
        return NULL;

    vmi_instance_t vmi = drakvuf->vmi;
    access_context_t ctx =
    {
        .addr = addr,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    return drakvuf_read_unicode_common(vmi, &ctx);
}

unicode_string_t* drakvuf_read_unicode_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return drakvuf_read_unicode_common(vmi, &ctx);
}

unicode_string_t* drakvuf_read_unicode32_common(vmi_instance_t vmi, const access_context_t* ctx)
{
    unicode_string_t* us = vmi_read_unicode_str_pm( vmi, ctx, VMI_PM_LEGACY );
    if ( !us )
        return NULL;

    unicode_string_t* out = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));

    if ( !out )
    {
        vmi_free_unicode_str(us);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(us, out, "UTF-8");
    vmi_free_unicode_str(us);

    if (VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

unicode_string_t* drakvuf_read_unicode32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    if ( !addr )
        return NULL;

    vmi_instance_t vmi = drakvuf->vmi;
    access_context_t ctx =
    {
        .addr = addr,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    return drakvuf_read_unicode32_common(vmi, &ctx);
}

unicode_string_t* drakvuf_read_unicode32_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .addr = vaddr,
        .pid = pid
    };

    return drakvuf_read_unicode32_common(vmi, &ctx);
}

size_t drakvuf_wchar_string_length(vmi_instance_t vmi, const access_context_t* ctx)
{
    access_context_t mutable_ctx = *ctx;

    size_t str_len = 0;
    uint16_t wchar = 1;
    for ( ; wchar ; str_len += 2 )
    {
        mutable_ctx.addr = ctx->addr + str_len;
        if ( VMI_FAILURE == vmi_read_16(vmi, &mutable_ctx, &wchar) )
        {
            str_len = 0;
            goto end;
        }
    }

end:
    return (str_len / 2);
}

unicode_string_t* drakvuf_read_wchar_array(vmi_instance_t vmi, const access_context_t* ctx, size_t length)
{
    unicode_string_t us;

    us.length = length * 2;
    us.contents = (uint8_t*)g_try_malloc0(sizeof(uint8_t) * (length * 2 + 2));

    if ( !us.contents )
        return NULL;

    if ( VMI_FAILURE == vmi_read(vmi, ctx, us.length, us.contents, NULL) )
    {
        g_free(us.contents);
        return NULL;
    }

    // end with NUL symbol
    us.contents[us.length] = 0;
    us.contents[us.length + 1] = 0;
    us.encoding = "UTF-16";

    unicode_string_t* out = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));

    if ( !out )
    {
        g_free(us.contents);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(&us, out, "UTF-8");
    g_free(us.contents);

    if (VMI_SUCCESS != rc)
    {
        if (out->contents)
            free(out->contents);
        memset((void*) out, 0, sizeof(*out));
        free(out);
        return NULL;
    }

    return out;
}

unicode_string_t* drakvuf_read_wchar_string(vmi_instance_t vmi, const access_context_t* ctx)
{
    size_t strlen = drakvuf_wchar_string_length(vmi, ctx);
    return drakvuf_read_wchar_array(vmi, ctx, strlen);
}

// Returns JSON-compliant copy of input string
gchar* drakvuf_escape_str(const char* input)
{
    char* result = NULL;
    struct json_object* obj = NULL;

    if (NULL == input)
    {
        // give caller result that can be freed
        result = g_strdup("\"(null)\"");
        goto exit;
    }

    obj = json_object_new_string(input);
    if (NULL == obj)
    {
        fprintf(stderr, "json_object_new_string() failed!\n");
        goto exit;
    }

    const char* escaped = json_object_to_json_string(obj);
    if (NULL == escaped)
    {
        fprintf(stderr, "json_object_to_json_string() failed!\n");
        goto exit;
    }

    result = g_strdup(escaped);
    if (NULL == result)
    {
        fprintf(stderr, "g_strdup() failed!\n");
    }

exit:
    json_object_put(obj); // passing NULL is OK
    return result;
}

static void drakvuf_event_fd_generate(drakvuf_t drakvuf)
{
    /* event_fds and fd_info_lookup are both generated based off of
       drakvuf->event_fd_info */
    if (drakvuf->event_fds != NULL)
    {
        PRINT_DEBUG("freeing existing event_fds\n");
        g_free(drakvuf->event_fds);
    }
    if (drakvuf->fd_info_lookup != NULL)
    {
        PRINT_DEBUG("freeing existing fd_info_lookup\n");
        g_free(drakvuf->fd_info_lookup);
    }

    /* allocate and populate new pollfd array and new fd_info_lookup array */
    drakvuf->event_fds = (struct pollfd*) g_try_malloc0(sizeof(struct pollfd) * \
                         (g_slist_length(drakvuf->event_fd_info)));

    drakvuf->fd_info_lookup = (fd_info_t) g_try_malloc0(sizeof(struct fd_info) * \
                              (g_slist_length(drakvuf->event_fd_info)));

    int i = 0;
    GSList* loop = drakvuf->event_fd_info;
    while (loop)
    {
        fd_info_t fd_info = (fd_info_t) loop->data;
        drakvuf->event_fds[i].fd = fd_info->fd;
        drakvuf->event_fds[i].events = POLLIN | POLLERR;
        PRINT_DEBUG("new event_fd i=%d for fd=%d\n", i, fd_info->fd);

        drakvuf->fd_info_lookup[i].fd = fd_info->fd;
        drakvuf->fd_info_lookup[i].event_cb = fd_info->event_cb;
        drakvuf->fd_info_lookup[i].data = fd_info->data;
        PRINT_DEBUG("new fd_info_lookup i=%d for fd=%d\n", i, fd_info->fd);

        loop = loop->next;
        i++;
    }

    return;
}

int drakvuf_event_fd_remove(drakvuf_t drakvuf, int fd)
{
    PRINT_DEBUG("drakvuf_event_fd_remove fd=%d\n", fd);
    int i = 0;
    GSList* loop = drakvuf->event_fd_info;
    while (loop)
    {
        fd_info_t fd_info = (fd_info_t) loop->data;
        if (fd_info->fd == fd)
        {
            PRINT_DEBUG("found match at index=%d\n", i);
            drakvuf->event_fd_info = g_slist_remove(drakvuf->event_fd_info, fd_info);

            drakvuf->event_fd_cnt = g_slist_length(drakvuf->event_fd_info);
            PRINT_DEBUG("regenerating event_fds and fd_info_lookup...\n");

            drakvuf_event_fd_generate(drakvuf);
            return 1;
        }
        loop = loop->next;
        i++;
    }
    PRINT_DEBUG("drakvuf_event_fd_remove could not find fd!\n");
    return 0;
}

int drakvuf_event_fd_add(drakvuf_t drakvuf, int fd, event_cb_t event_cb, void* data)
{
    PRINT_DEBUG("drakvuf_event_fd_add fd=%d\n", fd);

    /* add new fd_info */
    fd_info_t new_fd_info = (fd_info_t) g_try_malloc0(sizeof(struct fd_info));
    new_fd_info->fd = fd;
    new_fd_info->event_cb = event_cb;
    new_fd_info->data = data;
    /* the event_fd_info list is the authoritive data source used to
       create the event_fds and fd_info_lookup data structures */
    drakvuf->event_fd_info = g_slist_append(drakvuf->event_fd_info, new_fd_info);
    drakvuf->event_fd_cnt = g_slist_length(drakvuf->event_fd_info);
    PRINT_DEBUG("size of list=%d\n", drakvuf->event_fd_cnt);
    PRINT_DEBUG("regenerating event_fds and fd_info_lookup...\n");
    drakvuf_event_fd_generate(drakvuf);
    return 1;
}

bool drakvuf_set_vcpu_gprs(drakvuf_t drakvuf, unsigned int vcpu, registers_t* regs)
{
    vcpu_guest_context_any_t ctx;

    if ( !xen_get_vcpu_ctx(drakvuf->xen, drakvuf->domID, vcpu, &ctx) )
        return false;

    // HVM guests are always treated as x64 by Xen
    ctx.x64.user_regs.rip = regs->x86.rip;
    ctx.x64.user_regs.rax = regs->x86.rax;
    ctx.x64.user_regs.rbx = regs->x86.rbx;
    ctx.x64.user_regs.rcx = regs->x86.rcx;
    ctx.x64.user_regs.rdx = regs->x86.rdx;
    ctx.x64.user_regs.rbp = regs->x86.rbp;
    ctx.x64.user_regs.rsp = regs->x86.rsp;
    ctx.x64.user_regs.r8 = regs->x86.r8;
    ctx.x64.user_regs.r9 = regs->x86.r9;
    ctx.x64.user_regs.r10 = regs->x86.r10;
    ctx.x64.user_regs.r11 = regs->x86.r11;
    ctx.x64.user_regs.r12 = regs->x86.r12;
    ctx.x64.user_regs.r13 = regs->x86.r13;
    ctx.x64.user_regs.r14 = regs->x86.r14;
    ctx.x64.user_regs.r15 = regs->x86.r15;

    return xen_set_vcpu_ctx(drakvuf->xen, drakvuf->domID, vcpu, &ctx);
}

static bool is_valid_vcpu(drakvuf_t drakvuf, unsigned int vcpu)
{
    // VMs with more than MAX_DRAKVUF_VCPU vCPUs are not
    // supported for usage with IPT, this limit is DRAKVUF specific
    return vcpu < MAX_DRAKVUF_VCPU && drakvuf->vcpus > vcpu;
}

bool drakvuf_enable_ipt(drakvuf_t drakvuf, unsigned int vcpu, uint8_t** buf, uint64_t* size)
{
    if ( !is_valid_vcpu(drakvuf, vcpu) )
        return false;

    if ( !xen_enable_ipt(drakvuf->xen, drakvuf->domID, vcpu, &drakvuf->ipt_state[vcpu]) )
        return false;

    *buf = drakvuf->ipt_state[vcpu].buf;
    *size = drakvuf->ipt_state[vcpu].size;

    return true;
}

bool drakvuf_get_ipt_offset(drakvuf_t drakvuf, unsigned int vcpu, uint64_t* offset, uint64_t* last_offset)
{
    if ( !is_valid_vcpu(drakvuf, vcpu) )
        return false;

    if ( !xen_get_ipt_offset(drakvuf->xen, drakvuf->domID, vcpu, &drakvuf->ipt_state[vcpu]) )
        return false;

    *offset = drakvuf->ipt_state[vcpu].offset;
    *last_offset = drakvuf->ipt_state[vcpu].last_offset;

    return true;
}

bool drakvuf_disable_ipt(drakvuf_t drakvuf, unsigned int vcpu)
{
    if ( !is_valid_vcpu(drakvuf, vcpu) )
        return false;

    if ( !xen_disable_ipt(drakvuf->xen, drakvuf->domID, vcpu, &drakvuf->ipt_state[vcpu]) )
        return false;

    return true;
}
