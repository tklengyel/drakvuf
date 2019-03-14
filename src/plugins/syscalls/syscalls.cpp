/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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
#include <assert.h>
#include "syscalls.h"
#include "winscproto.h"
#include "linuxscproto.h"


static char* extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    if ( arg.dir == DIR_IN || arg.dir == DIR_INOUT )
    {
        if ( arg.type == PUNICODE_STRING )
        {
            unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
            if ( us )
            {
                char* str = (char*)us->contents;
                us->contents = nullptr;
                vmi_free_unicode_str(us);
                return str;
            }
        }

        else if ( arg.type == PCHAR )
        {
            char* str = drakvuf_read_ascii_str(drakvuf, info, val);
            return str;
        }

        if ( !strcmp(arg.name, "FileHandle") )
        {
            char* filename = drakvuf_get_filename_from_handle(drakvuf, info, val);
            if ( filename ) return filename;
        }
    }

    return nullptr;
}

static void print_header(output_format_t format, drakvuf_t drakvuf, const drakvuf_trap_info_t* info)
{
    gchar* escaped_pname = NULL;

    switch (format)
    {
        case OUTPUT_CSV:
            printf("syscall," FORMAT_TIMEVAL ",%" PRIu32" 0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->breakpoint.module, info->trap->name);
            break;
        case OUTPUT_KV:
            printf("syscall Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name);
            break;
        case OUTPUT_JSON:
            // print_footer() puts single EOL at end of JSON doc to simplify parsing on other end
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"syscall\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"VCPU\": %" PRIu32 ","
                    "\"CR3\": %" PRIu64 ","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Module\": \"%s\","
                    "\"Method\": \"%s\","
                    "\"Args\": [",
                    UNPACK_TIMEVAL(info->timestamp),
                    info->vcpu, info->regs->cr3, escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->breakpoint.module, info->trap->name);
            g_free(escaped_pname);
            break;

        case OUTPUT_DEFAULT:
        default:
            printf("[SYSCALL] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" %s!%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   info->trap->breakpoint.module, info->trap->name);
            break;
    }
}

static void print_nargs(output_format_t format, uint32_t nargs)
{
    switch (format)
    {
        case OUTPUT_CSV:
            printf(",%" PRIu32, nargs);
            break;
        case OUTPUT_KV:
        case OUTPUT_JSON:
            break;
        default:
        case OUTPUT_DEFAULT:
            printf(" Arguments: %" PRIu32 "\n", nargs);
            break;
    }
}

static void print_csv_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val, const char* str)
{
    printf(",%s,%s,%s,", arg_direction_names[arg.dir], type_names[arg.type], arg.name);

    if ( 4 == s->reg_size )
        printf("0x%" PRIx32 ",", static_cast<uint32_t>(val));
    else
        printf("0x%" PRIx64 ",", static_cast<uint64_t>(val));

    if ( str )
    {
        printf("%s", str);
    }

    printf(",");
}

static void print_kv_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val, const char* str)
{
    if ( str )
    {
        printf(",%s=\"%s\"", arg.name, str);
        return;
    }

    if ( 4 == s->reg_size )
        printf(",%s=0x%" PRIx32, arg.name, static_cast<uint32_t>(val));
    else
        printf(",%s=0x%" PRIx64, arg.name, static_cast<uint64_t>(val));
}


static void print_json_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscall_t* sc, size_t i, addr_t val, const char* str)
{
    const arg_t& arg = sc->args[i];

    if ( str )
    {
        gchar* escaped = drakvuf_escape_str(str);
        printf("{\"%s\" : %s}", arg.name, escaped);
        g_free(escaped);
    }
    else
    {
        if ( 4 == s->reg_size )
            printf("{\"%s\" :%"  PRIu32 "}", arg.name, static_cast<uint32_t>(val));
        else
            printf("{\"%s\" :%" PRIu64 "}", arg.name, static_cast<uint64_t>(val));
    }

    if (i < sc->num_args-1)
        printf(",");
}

static void print_default_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val, const char* str)
{
    printf("\t%s %s %s: ", arg_direction_names[arg.dir], type_names[arg.type], arg.name);

    if ( 4 == s->reg_size )
        printf("0x%" PRIx32, static_cast<uint32_t>(val));
    else
        printf("0x%" PRIx64, static_cast<uint64_t>(val));

    if ( str )
    {
        printf(" -> '%s'", str);
    }

    printf("\n");
}

static void print_args(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscall_t* sc, unsigned char* args_data)
{
    size_t nargs = sc->num_args;
    uint32_t* args_data32 = (uint32_t*)args_data;
    uint64_t* args_data64 = (uint64_t*)args_data;

    for ( size_t i=0; i<nargs; i++ )
    {
        addr_t val = ( 4 == s->reg_size ) ? args_data32[i] : args_data64[i];

        char* str = extract_string(drakvuf, info, sc->args[i], val);

        switch (s->format)
        {
            case OUTPUT_CSV:
                print_csv_arg(s, drakvuf, info, sc->args[i], val, str);
                break;
            case OUTPUT_KV:
                print_kv_arg(s, drakvuf, info, sc->args[i], val, str);
                break;
            case OUTPUT_JSON:
                print_json_arg(s, drakvuf, info, sc, i, val, str);
                break;
            default:
            case OUTPUT_DEFAULT:
                print_default_arg(s, drakvuf, info, sc->args[i], val, str);
                break;
        }

        g_free(str);
    }
}

static void print_footer(output_format_t format, uint32_t nargs)
{
    switch (format)
    {
        case OUTPUT_CSV:
            printf("\n");
            break;
        case OUTPUT_KV:
            printf("\n");
            break;
        case OUTPUT_JSON:
            // close JSON args array and document
            printf("] }\n");
            break;
        default:
        case OUTPUT_DEFAULT:
            if ( nargs == 0 )
                printf("\n");
            break;
    }
}

// Builds the argument buffer from the current context, returns status
static int linux_build_argbuf(uint8_t* buf, vmi_instance_t vmi, drakvuf_trap_info_t* info, const syscall_t* sc)
{
    int nargs = 0;
    int rc = VMI_SUCCESS;
    syscall_wrapper_t* wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls* s = wrapper->sc;

    if (NULL == sc)
    {
        rc = VMI_FAILURE;
        goto exit;
    }

    nargs = sc->num_args;

    // get arguments only if we know how many to get
    if (0 == nargs)
    {
        goto exit;
    }

    // Now now, only support legacy syscall arg passing on 32 bit
    if ( 4 == s->reg_size )
    {
        uint32_t* buf32 = (uint32_t*)buf;
        if ( nargs > 0 )
            buf32[0] = (uint32_t) info->regs->rbx;
        if ( nargs > 1 )
            buf32[1] = (uint32_t) info->regs->rcx;
        if ( nargs > 2 )
            buf32[2] = (uint32_t) info->regs->rdx;
        if ( nargs > 3 )
            buf32[3] = (uint32_t) info->regs->rsi;
        if ( nargs > 4 )
            buf32[4] = (uint32_t) info->regs->rdi;
    }
    else if ( 8 == s->reg_size )
    {
        uint64_t* buf64 = (uint64_t*)buf;

        // Support both calling conventions for 64 bit Linux syscalls
        if (wrapper->flags & SYSCALL_FLAG_LINUX_PT_REGS)
        {
            // The syscall args are passed via a struct pt_regs *, which is in %rdi upon entry
            struct linux_pt_regs lr;
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = info->regs->rdi,
            };

            rc = vmi_read(vmi, &ctx, sizeof(lr), &lr, NULL);
            if (VMI_SUCCESS != rc)
            {
                fprintf(stderr, "vmi_read_va(%p) failed\n", (void*)ctx.addr);
                goto exit;
            }

            if ( nargs > 0 )
                buf64[0] = lr.rdi;
            if ( nargs > 1 )
                buf64[1] = lr.rsi;
            if ( nargs > 2 )
                buf64[2] = lr.rdx;
            if ( nargs > 3 )
                buf64[3] = lr.r10;
            if ( nargs > 4 )
                buf64[4] = lr.r8;
            if ( nargs > 5 )
                buf64[5] = lr.r9;
        }
        else
        {
            // The args are passed directly via registers in sycall context
            if ( nargs > 0 )
                buf64[0] = info->regs->rdi;
            if ( nargs > 1 )
                buf64[1] = info->regs->rsi;
            if ( nargs > 2 )
                buf64[2] = info->regs->rdx;
            if ( nargs > 3 )
                buf64[3] = info->regs->r10;
            if ( nargs > 4 )
                buf64[4] = info->regs->r8;
            if ( nargs > 5 )
                buf64[5] = info->regs->r9;
        }
    }

exit:
    return rc;
}

static event_response_t linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    unsigned int nargs = 0;
    uint8_t buf[sizeof(uint64_t) * 8] = {0};

    syscall_wrapper_t* wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls* s = wrapper->sc;
    const syscall_t* sc = NULL;

    if (wrapper->syscall_index>-1 )
    {
        sc = &linux_syscalls[wrapper->syscall_index];
        nargs = sc->num_args;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    (void)vmi;

    int rc = linux_build_argbuf(buf, vmi, info, sc);
    if (VMI_SUCCESS != rc)
    {
        // Don't extract any args
        nargs = 0;
    }

    print_header(s->format, drakvuf, info);
    if ( nargs )
    {
        print_nargs(s->format, nargs);
        print_args(s, drakvuf, info, sc, buf);
    }
    print_footer(s->format, nargs);

    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t win_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    unsigned int nargs = 0;
    size_t size = 0;
    unsigned char* buf = NULL; // pointer to buffer to hold argument values

    syscall_wrapper_t* wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls* s = wrapper->sc;
    const syscall_t* sc = NULL;

    if (wrapper->syscall_index>-1 )
    {
        // need to malloc buf before setting type of each array cell
        sc = &win_syscalls[wrapper->syscall_index];
        nargs = sc->num_args;
        size = s->reg_size * nargs;
        buf = (unsigned char*)g_malloc(sizeof(char)*size);
    }

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
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, size, buf, NULL) )
                goto exit;
        }
        else
        {
            // 64 bit os
            uint64_t* buf64 = (uint64_t*)buf;
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
                if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &(buf64[4]), NULL) )
                    goto exit;
            }
        }
    }

    print_header(s->format, drakvuf, info);
    if ( nargs )
    {
        print_nargs(s->format, nargs);
        print_args(s, drakvuf, info, sc, buf);
    }
    print_footer(s->format, nargs);

exit:
    g_free(buf);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static GSList* create_trap_config(drakvuf_t drakvuf, syscalls* s, symbols_t* symbols)
{

    GSList* ret = NULL;
    unsigned long i;
    unsigned long j;

    PRINT_DEBUG("Received %lu symbols\n", symbols->count);

    if ( s->os == VMI_OS_WINDOWS )
    {
        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);

        if ( !ntoskrnl )
            return NULL;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol* symbol = &symbols->symbols[i];

            if (strncmp(symbol->name, "Nt", 2))
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s\n", symbol->name);

            syscall_wrapper_t* wrapper = (syscall_wrapper_t*)g_malloc(sizeof(syscall_wrapper_t));

            wrapper->syscall_index = -1;
            wrapper->sc=s;

            for (j=0; j<NUM_SYSCALLS_WIN; j++)
            {
                if ( !strcmp(symbol->name,win_syscalls[j].name) )
                {
                    wrapper->syscall_index=j;
                    break;
                }
            }

            if ( wrapper->syscall_index==-1 )
                PRINT_DEBUG("[SYSCALLS]: %s not found in argument list\n", symbol->name);

            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
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

        if ( !drakvuf_get_constant_rva(drakvuf, "_text", &rva) )
            return NULL;

        addr_t kaslr = drakvuf_get_kernel_base(drakvuf) - rva;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol* symbol = &symbols->symbols[i];

            /* Looking for system calls */
            if (!strncmp(symbol->name, "sys_", 4) )
            {
                /* This is the address of the table itself so skip it */
                if (!strcmp(symbol->name, "sys_call_table"))
                    continue;

                /* These are all variables, not syscalls */
                if (!strncmp(symbol->name, "sys_dmi", 7)              ||
                        !strcmp(symbol->name,  "sys_tz")                  || /* used by gettimeofday */
                        !strcmp(symbol->name,  "sys_tracepoint_refcount") ||
                        !strcmp(symbol->name,  "sys_table")               ||
                        !strcmp(symbol->name,  "sys_perf_refcount_enter") ||
                        !strcmp(symbol->name,  "sys_perf_refcount_exit")   )
                    continue;
            }
            else if ( strncmp(symbol->name, "__x64_sys_", 10) )
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s at 0x%lx (kaslr 0x%lx)\n", symbol->name, symbol->rva + kaslr, kaslr);

            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 0;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = symbol->rva + kaslr;
            trap->breakpoint.module = "linux";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = linux_cb;
            //trap->data = s;

            syscall_wrapper_t* wrapper = (syscall_wrapper_t*)g_malloc(sizeof(syscall_wrapper_t));
            wrapper->syscall_index = -1;
            wrapper->sc = s;
            wrapper->flags = 0;

            /* Record symbol's index for faster lookup */
            for (j=0; j<NUMBER_OF(linux_syscalls); j++)
            {
                // See kernel: arch/x86/include/asm/syscall_wrapper.h
                //             arch/x86/entry/entry_64.S
                char alt_name[32] = {0};

                assert(strlen(linux_syscalls[j].name) < sizeof(alt_name) - 6);
                (void) snprintf( alt_name, sizeof(alt_name), "__x64_%s", linux_syscalls[j].name);

                if (!strcmp(symbol->name, linux_syscalls[j].name))
                {
                    wrapper->syscall_index = j;
                }
                else if (!strcmp(symbol->name, alt_name))
                {
                    wrapper->syscall_index = j;
                    wrapper->flags |= SYSCALL_FLAG_LINUX_PT_REGS;
                    break;
                }
            }

            trap->data = wrapper;

            ret = g_slist_prepend(ret, trap);
        }
    }

    return ret;
}

static GHashTable* read_syscalls_filter(const char* filter_file)
{
    GHashTable* table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    if (!table) return NULL;

    FILE* f = fopen(filter_file, "r");
    if (!f)
    {
        g_hash_table_destroy(table);
        return NULL;
    }
    ssize_t read;
    do
    {
        char* line = NULL;
        size_t len = 0;
        read = getline(&line, &len, f);
        while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) read--;
        if (read > 0)
        {
            line[read] = '\0';
            g_hash_table_insert(table, line, NULL);
        }
        else
            free(line);
    }
    while (read != -1);

    fclose(f);
    return table;
}

static symbols_t* filter_symbols(const symbols_t* symbols, const char* filter_file)
{
    GHashTable* filter = read_syscalls_filter(filter_file);
    if (!filter) return NULL;
    symbols_t* ret = (symbols_t*)g_malloc0(sizeof(symbols_t));
    if (!ret)
    {
        g_hash_table_destroy(filter);
        return NULL;
    }

    ret->count = symbols->count;
    ret->symbols = (symbol_t*)g_malloc0(sizeof(symbol_t) * ret->count);
    if (!ret->symbols)
    {
        g_hash_table_destroy(filter);
        g_free(ret);
        return NULL;
    }

    size_t filtered_size = 0;
    for (size_t i = 0; i < symbols->count; ++i)
    {
        if (g_hash_table_contains(filter, symbols->symbols[i].name))
        {
            ret->symbols[filtered_size] = symbols->symbols[i];
            ret->symbols[filtered_size].name = g_strdup(symbols->symbols[i].name);
            filtered_size++;
        }
    }
    ret->count = filtered_size;
    g_hash_table_destroy(filter);
    return ret;
}

syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* c, output_format_t output)
{
    symbols_t* symbols = drakvuf_get_symbols_from_rekall(drakvuf);
    if (!symbols)
    {
        fprintf(stderr, "Failed to get symbols from Rekall profile\n");
        throw -1;
    }

    if (c->syscalls_filter_file)
    {
        symbols_t* filtered_symbols = filter_symbols(symbols, c->syscalls_filter_file);
        drakvuf_free_symbols(symbols);
        if (!filtered_symbols)
        {
            fprintf(stderr, "Failed to apply syscalls filter %s\n", c->syscalls_filter_file);
            throw -1;
        }
        symbols = filtered_symbols;
    }

    this->os = drakvuf_get_os_type(drakvuf);
    this->traps = create_trap_config(drakvuf, this, symbols);
    this->format = output;

    if ( !this->traps )
    {
        drakvuf_free_symbols(symbols);
        throw -1;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->reg_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    drakvuf_release_vmi(drakvuf);

    drakvuf_free_symbols(symbols);

    bool error = 0;
    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;

        if ( !drakvuf_add_trap(drakvuf, trap) )
        {
            error = 1;
            break;
        }

        loop = loop->next;
    }

    if ( error )
    {
        loop = this->traps;
        while (loop)
        {
            drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;
            drakvuf_remove_trap(drakvuf, trap, NULL);
            g_free(trap->data);
            g_free((gpointer)trap->name);
            g_free(trap);
            loop = loop->next;
        }

        g_slist_free(this->traps);
        this->traps = NULL;

        throw -1;
    }
}

syscalls::~syscalls()
{
    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;
        g_free((char*)trap->name);
        if (trap->data != (void*)this)
        {
            g_free(trap->data);
        }
        g_free(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}
