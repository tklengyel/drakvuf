/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                  *
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

#include <glib.h>
#include "../xen_helper/xen_helper.h"

#include "libdrakvuf.h"
#include "private.h"
#include "rekall-profile.h"

#ifdef DRAKVUF_DEBUG
bool verbose = 0;
#endif

void drakvuf_close(drakvuf_t drakvuf, const bool pause) {
    if (!drakvuf)
        return;

    if (drakvuf->vmi) {
        close_vmi(drakvuf);
    }

    if (drakvuf->xen) {

        if ( !pause )
            drakvuf_force_resume(drakvuf);

        xen_free_interface(drakvuf->xen);
    }

    g_free(drakvuf->offsets);
    g_free(drakvuf->sizes);
    g_mutex_clear(&drakvuf->vmi_lock);
    g_free(drakvuf->dom_name);
    g_free(drakvuf->rekall_profile);
    g_free(drakvuf);
}

bool drakvuf_init(drakvuf_t *drakvuf, const char *domain, const char *rekall_profile, bool _verbose) {

    if ( !domain || !rekall_profile )
        return 0;

#ifdef DRAKVUF_DEBUG
    verbose = _verbose;
#endif

    *drakvuf = g_malloc0(sizeof(struct drakvuf));
    (*drakvuf)->rekall_profile = g_strdup(rekall_profile);
    (*drakvuf)->os = rekall_get_os_type(rekall_profile);

    g_mutex_init(&(*drakvuf)->vmi_lock);

    if ( !xen_init_interface(&(*drakvuf)->xen) )
        goto err;

    get_dom_info((*drakvuf)->xen, domain, &(*drakvuf)->domID, &(*drakvuf)->dom_name);
    domid_t test = ~0;
    if ( (*drakvuf)->domID == test )
        goto err;

    drakvuf_pause(*drakvuf);

    if (!init_vmi(*drakvuf)) {
        drakvuf_resume(*drakvuf);
        goto err;
    }

    switch((*drakvuf)->os) {
    case VMI_OS_WINDOWS:
        if ( !set_os_windows(*drakvuf) )
            goto err;
        break;
    case VMI_OS_LINUX:
        if ( !set_os_linux(*drakvuf) )
            goto err;
        break;
    default:
        fprintf(stderr, "The Rekall profile describes an unknown operating system kernel!\n");
        goto err;
    };

    PRINT_DEBUG("libdrakvuf initialized\n");

    return 1;

err:
    drakvuf_close(*drakvuf, 1);
    *drakvuf = NULL;

    PRINT_DEBUG("libdrakvuf initialization failed\n");

    return 0;
}

void drakvuf_interrupt(drakvuf_t drakvuf, int sig) {
    drakvuf->interrupted = sig;
}

bool inject_trap_breakpoint(drakvuf_t drakvuf, drakvuf_trap_t *trap) {

    if(trap->breakpoint.lookup_type == LOOKUP_NONE) {
        return inject_trap_pa(drakvuf, trap, trap->breakpoint.addr);
    }

    if(trap->breakpoint.lookup_type == LOOKUP_PID || trap->breakpoint.lookup_type == LOOKUP_NAME) {
        if (trap->breakpoint.addr_type == ADDR_RVA && trap->breakpoint.module) {

            vmi_pid_t pid = -1;
            const char *name = NULL;
            addr_t module_list = 0;

            if(trap->breakpoint.pid == 4 || !strcmp(trap->breakpoint.proc, "System")) {

                pid = 4;
                name = "System";
                if(VMI_FAILURE == vmi_read_addr_ksym(drakvuf->vmi, "PsLoadedModuleList", &module_list))
                    return 0;

            } else {

                /* Process library */
                addr_t process_base;

                if(trap->breakpoint.lookup_type == LOOKUP_PID)
                    pid = trap->breakpoint.pid;
                if(trap->breakpoint.lookup_type == LOOKUP_NAME)
                    name = trap->breakpoint.proc;

                if( !drakvuf_find_process(drakvuf, pid, name, &process_base) )
                    return 0;

                if (pid == -1)
                {
                    if ( drakvuf_get_process_pid(drakvuf, process_base, &pid) == VMI_FAILURE )
                        return 0;
                }

                if( !drakvuf_get_module_list(drakvuf, process_base, &module_list) )
                    return 0;
            }

            return inject_traps_modules(drakvuf, trap, module_list, pid);
        }

        if(trap->breakpoint.addr_type == ADDR_VA) {
            addr_t dtb = vmi_pid_to_dtb(drakvuf->vmi, trap->breakpoint.pid);
            if (!dtb)
            {
                PRINT_DEBUG("No DTB found for pid %i\n", trap->breakpoint.pid);
                return 0;
            }

            addr_t trap_pa = vmi_pagetable_lookup(drakvuf->vmi, dtb, trap->breakpoint.addr);
            if (!trap_pa)
            {
                PRINT_DEBUG("Failed to find PA for breakpoint VA addr 0x%lx in DTB 0x%lx\n", trap->breakpoint.addr, dtb);
                return 0;
            }

            return inject_trap_pa(drakvuf, trap, trap_pa);
        }

        if(trap->breakpoint.addr_type == ADDR_PA) {
            fprintf(stderr, "DRAKVUF Trap misconfiguration: PID lookup specified for PA location\n");
            return 0;
        }
    }

    if(trap->breakpoint.lookup_type == LOOKUP_DTB) {
        if(trap->breakpoint.addr_type == ADDR_VA) {
            addr_t trap_pa = vmi_pagetable_lookup(drakvuf->vmi, trap->breakpoint.dtb, trap->breakpoint.addr);
            PRINT_DEBUG("Breakpoint VA 0x%" PRIx64" -> PA 0x%" PRIx64 "\n", trap->breakpoint.addr, trap_pa);
            if (!trap_pa)
                return 0;

            return inject_trap_pa(drakvuf, trap, trap_pa);
        }

        //TODO: ADDR_RVA
    }

    return 0;
}

bool inject_trap_reg(drakvuf_t drakvuf, drakvuf_trap_t *trap) {
    if(CR3 == trap->reg) {
        drakvuf->cr3 = g_slist_prepend(drakvuf->cr3, trap);
        return 1;
    }

    fprintf(stderr, "Support for trapping requested register is not (yet) implemented!\n");

    return 0;
}

bool inject_trap_debug(drakvuf_t drakvuf, drakvuf_trap_t *trap) {
    if ( !drakvuf->debug && !control_debug_trap(drakvuf, 1) )
        return 0;

    drakvuf->debug = g_slist_prepend(drakvuf->debug, trap);
    return 1;
};

bool inject_trap_cpuid(drakvuf_t drakvuf, drakvuf_trap_t *trap) {
    if ( !drakvuf->cpuid && !control_cpuid_trap(drakvuf, 1) )
        return 0;

    drakvuf->cpuid = g_slist_prepend(drakvuf->cpuid, trap);
    return 1;
};

bool drakvuf_add_trap(drakvuf_t drakvuf, drakvuf_trap_t *trap) {

    bool ret;

    if (!trap || !trap->cb)
        return 0;

    if(g_hash_table_lookup(drakvuf->remove_traps, &trap)) {
        g_hash_table_remove(drakvuf->remove_traps, &trap);
        return 1;
    }

    drakvuf_pause(drakvuf);

    switch(trap->type) {
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
        default:
            ret = 0;
            break;
    }

    drakvuf_resume(drakvuf);
    return ret;
}

void drakvuf_remove_trap(drakvuf_t drakvuf, drakvuf_trap_t *trap,
                         drakvuf_trap_free_t free_routine)
{
    if ( drakvuf->in_callback) {
        struct free_trap_wrapper *free_wrapper =
            g_hash_table_lookup(drakvuf->remove_traps, &trap);

        if (!free_wrapper) {
            free_wrapper = g_malloc0(sizeof(struct free_trap_wrapper));
            free_wrapper->free_routine = free_routine;
            free_wrapper->trap = trap;
            g_hash_table_insert(drakvuf->remove_traps,
                                g_memdup(&trap, sizeof(void*)),
                                free_wrapper);
        }

        free_wrapper->counter++;
    } else {
        remove_trap(drakvuf, trap);
        if(free_routine)
            free_routine(trap);
    }
}

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf) {
    g_mutex_lock(&drakvuf->vmi_lock);
    return drakvuf->vmi;
}

void drakvuf_release_vmi(drakvuf_t drakvuf) {
    g_mutex_unlock(&drakvuf->vmi_lock);
}

void drakvuf_pause (drakvuf_t drakvuf) {
    xen_pause(drakvuf->xen, drakvuf->domID);
}

void drakvuf_resume (drakvuf_t drakvuf) {
    xen_resume(drakvuf->xen, drakvuf->domID);
}

void drakvuf_force_resume (drakvuf_t drakvuf) {
    xen_force_resume(drakvuf->xen, drakvuf->domID);
}

bool drakvuf_get_struct_size(const char *rekall_profile,
                             const char *struct_name,
                             size_t *size)
{
    return rekall_lookup(
                rekall_profile,
                struct_name,
                NULL,
                NULL,
                size);
}

bool drakvuf_get_struct_member_rva(const char *rekall_profile,
                                   const char *struct_name,
                                   const char *symbol,
                                   addr_t *rva)
{
    return rekall_lookup(
                rekall_profile,
                struct_name,
                symbol,
                rva,
                NULL);
}

const char *drakvuf_get_rekall_profile(drakvuf_t drakvuf) {
    return drakvuf->rekall_profile;
}

addr_t drakvuf_get_kernel_base(drakvuf_t drakvuf) {
    return drakvuf->kernbase;
}

os_t drakvuf_get_os_type(drakvuf_t drakvuf) {
    return drakvuf->os;
}
