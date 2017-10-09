/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include "syscalls.h"
#include "winscproto.h"

static event_response_t linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    syscalls *s = (syscalls*)info->trap->data;

    switch(s->format) {
    case OUTPUT_CSV:
        printf("syscall,%" PRIu32" 0x%" PRIx64 ",%s,%" PRIi64 ",%s,%s\n",
               info->vcpu, info->regs->cr3, info->proc_data->name, info->proc_data->userid, info->trap->breakpoint.module, info->trap->name);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SYSCALL] vCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64" %s!%s\n",
               info->vcpu, info->regs->cr3, info->proc_data->name,
               USERIDSTR(drakvuf), info->proc_data->userid,
               info->trap->breakpoint.module, info->trap->name);
        break;
    }

    return 0;
}

static unicode_string_t* read_unicode(vmi_instance_t vmi, access_context_t *ctx)
{
    unicode_string_t *us = vmi_read_unicode_str(vmi, ctx);
    if ( !us )
        return NULL;

    unicode_string_t *out = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));

    if ( !out ) {
        vmi_free_unicode_str(us);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(us, out, "UTF-8");
    vmi_free_unicode_str(us);

    if(VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

static unicode_string_t* get_filename_from_handle(syscalls *s,
                                                  drakvuf_t drakvuf,
                                                  drakvuf_trap_info_t *info,
                                                  vmi_instance_t vmi,
                                                  access_context_t *ctx,
                                                  addr_t handle)
{
    addr_t process=drakvuf_get_current_process(drakvuf, info->vcpu);

    if (!process)
        return NULL;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);
    if ( !obj )
        return NULL;

    ctx->addr = obj + s->object_header_body + s->file_object_filename;
    return read_unicode(vmi, ctx);
}

static event_response_t win_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    unsigned int i = 0, nargs = 0;
    size_t size = 0;
    unsigned char* buf = NULL; // pointer to buffer to hold argument values

    syscall_wrapper_t *wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls *s = wrapper->sc;
    const win_syscall_t *wsc = NULL;

    if (wrapper->syscall_index>-1 )
    {
        // need to malloc buf before setting type of each array cell
        wsc = &win_syscalls[wrapper->syscall_index];
        nargs = wsc->num_args;
        size = s->reg_size * nargs;
        buf = (unsigned char *)g_malloc(sizeof(char)*size);
    }

    uint32_t *buf32 = (uint32_t *)buf;
    uint64_t *buf64 = (uint64_t *)buf;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if ( nargs )
    {
        // get arguments only if we know how many to get

        if ( 4 == s->reg_size )
        {
            // 32 bit os
            ctx.addr = info->regs->rsp + s->reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( size != vmi_read(vmi, &ctx, buf, size) )
                goto exit;
        }

        if ( 8 == s->reg_size )
        {
            if ( nargs > 0 )
                buf64[0] = info->regs->rcx;
            if ( nargs > 1 )
                buf64[1] = info->regs->rdx;
            if ( nargs > 2 )
                buf64[2] = info->regs->r8;
            if ( nargs > 3 )
                buf64[3] = info->regs->r9;
            if ( nargs > 4 )
            {
                // first 4 agrs passed via rcx, rdx, r8, and r9
                ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
                size_t sp_size = s->reg_size * (nargs-4);
                if ( sp_size != vmi_read(vmi, &ctx, &(buf64[4]), sp_size) )
                    goto exit;
           }
        }
    }

    switch(s->format) {
    case OUTPUT_CSV:
        printf("syscall,%" PRIu32" 0x%" PRIx64 ",%s,%" PRIi64 ",%s,%s",
               info->vcpu, info->regs->cr3, info->proc_data->name, info->proc_data->userid, info->trap->breakpoint.module, info->trap->name);

        if ( nargs )
        {
            printf(",%" PRIu32,nargs);

            for ( i=0; i<nargs; i++ )
            {
                addr_t val = 0;
                printf(",%s,%s,%s,",win_arg_direction_names[wsc->args[i].dir],win_type_names[wsc->args[i].type],wsc->args[i].name);

                if ( 4 == s->reg_size ) {
                    val = buf32[i];
                    printf("0x%" PRIx32",", buf32[i]);
                } else {
                    val = buf64[i];
                    printf("0x%" PRIx64",", buf64[i]);
                }

                if ( wsc->args[i].dir == DIR_IN || wsc->args[i].dir == DIR_INOUT )
                {
                    if ( wsc->args[i].type == PUNICODE_STRING) {
                        ctx.addr = val;
                        unicode_string_t *us = read_unicode(vmi, &ctx);

                        if ( us ) {
                            printf("%s", us->contents);
                            vmi_free_unicode_str(us);
                        }
                    }

                    if ( !strcmp(wsc->args[i].name, "FileHandle") ) {
                        unicode_string_t *us = get_filename_from_handle(s, drakvuf, info, vmi, &ctx, val);

                        if ( us ) {
                            printf("%s", us->contents);
                            vmi_free_unicode_str(us);
                        }
                    }
                }

                printf(",");
            }
        }

        printf("\n");
        break;
      default:
      case OUTPUT_DEFAULT:
        printf("[SYSCALL] vCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64" %s!%s",
               info->vcpu, info->regs->cr3, info->proc_data->name,
               USERIDSTR(drakvuf), info->proc_data->userid,
               info->trap->breakpoint.module, info->trap->name);

        if ( nargs )
        {
            printf(" Arguments: %" PRIu32 "\n",nargs);

            for( i =0; i<nargs; i++ )
            {
                addr_t val = 0;
                printf("\t%s %s %s: ", win_arg_direction_names[wsc->args[i].dir], win_type_names[wsc->args[i].type], wsc->args[i].name);

                if ( 4 == s->reg_size ) {
                    val = buf32[i];
                    printf("0x%" PRIx32, buf32[i]);
                } else {
                    val = buf64[i];
                    printf("0x%" PRIx64, buf64[i]);
                }

                if ( wsc->args[i].dir == DIR_IN || wsc->args[i].dir == DIR_INOUT )
                {
                    if ( wsc->args[i].type == PUNICODE_STRING) {
                        ctx.addr = val;
                        unicode_string_t *us = read_unicode(vmi, &ctx);

                        if ( us ) {
                            printf(" -> '%s'", us->contents);
                            vmi_free_unicode_str(us);
                        }
                    }

                    if ( !strcmp(wsc->args[i].name, "FileHandle") ) {
                        unicode_string_t *us = get_filename_from_handle(s, drakvuf, info, vmi, &ctx, val);

                        if ( us ) {
                            printf(" -> '%s'", us->contents);
                            vmi_free_unicode_str(us);
                        }
                    }
                }

                printf("\n");
            }
        } else
            printf("\n");
    }
exit:
    g_free(buf);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static GSList* create_trap_config(drakvuf_t drakvuf, syscalls *s, symbols_t *symbols, const char* rekall_profile) {

    GSList *ret = NULL;
    unsigned long i,j;

    PRINT_DEBUG("Received %lu symbols\n", symbols->count);

    if ( s->os == VMI_OS_WINDOWS )
    {
        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);

        if ( !ntoskrnl )
            return NULL;

        if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_HEADER", "Body", &s->object_header_body) )
            return NULL;
        if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_OBJECT", "FileName", &s->file_object_filename) )
            return NULL;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol *symbol = &symbols->symbols[i];

            if (strncmp(symbol->name, "Nt", 2))
                continue;
            //if (strcmp(symbol->name, "NtCallbackReturn"))
            //    continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s\n", symbol->name);

            syscall_wrapper_t *wrapper = (syscall_wrapper_t *)g_malloc(sizeof(syscall_wrapper_t));

            wrapper->syscall_index = -1;
            wrapper->sc=s;

            for (j=0; j<NUM_SYSCALLS; j++)
            {
                if ( !strcmp(symbol->name,win_syscalls[j].name) )
                {
                    wrapper->syscall_index=j;
                    break;
                }
            }

            if ( wrapper->syscall_index==-1 )
                PRINT_DEBUG("[SYSCALLS]: %s not found in argument list\n", symbol->name);

            drakvuf_trap_t *trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 4;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ntoskrnl + symbol->rva;
            trap->breakpoint.module = "ntoskrnl.exe";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = win_cb;
            trap->data = wrapper;

            ret = g_slist_prepend(ret, trap);
        }
    }

    if ( s->os == VMI_OS_LINUX )
    {
        addr_t rva = 0;

        if ( !drakvuf_get_constant_rva(rekall_profile, "_text", &rva) )
            return NULL;

        addr_t kaslr = drakvuf_get_kernel_base(drakvuf) - rva;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol *symbol = &symbols->symbols[i];

            /* Looking for system calls */
            if (strncmp(symbol->name, "sys_", 4) )
                continue;

            /* This is the address of the table itself so skip it */
            if (!strcmp(symbol->name, "sys_call_table") )
                continue;

            //if (strcmp(symbol->name, "sys_gettimeofday"))
            //    continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s at 0x%lx (kaslr 0x%lx)\n", symbol->name, symbol->rva + kaslr, kaslr);

            drakvuf_trap_t *trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 0;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = symbol->rva + kaslr;
            trap->breakpoint.module = "linux";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = linux_cb;
            trap->data = s;

            ret = g_slist_prepend(ret, trap);
        }
    }

    return ret;
}

syscalls::syscalls(drakvuf_t drakvuf, const void *config, output_format_t output) {
    const char *rekall_profile = (const char *)config;
    symbols_t *symbols = drakvuf_get_symbols_from_rekall(rekall_profile);
    if (!symbols)
    {
        fprintf(stderr, "Failed to parse Rekall profile at %s\n", rekall_profile);
        throw -1;
    }

    this->os = drakvuf_get_os_type(drakvuf);
    this->traps = create_trap_config(drakvuf, this, symbols, rekall_profile);
    this->format = output;

    if ( !this->traps )
        throw -1;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->reg_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    drakvuf_release_vmi(drakvuf);

    drakvuf_free_symbols(symbols);

    GSList *loop = this->traps;
    while(loop) {
        drakvuf_trap_t *trap = (drakvuf_trap_t *)loop->data;

        if ( !drakvuf_add_trap(drakvuf, trap) )
            throw -1;

        loop = loop->next;
    }
}

syscalls::~syscalls() {
    GSList *loop = this->traps;
    while(loop) {
        drakvuf_trap_t *trap = (drakvuf_trap_t *)loop->data;
        g_free((char*)trap->name);
        if (trap->data != (void*)this) {
            g_free(trap->data);
        }
        g_free(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}
