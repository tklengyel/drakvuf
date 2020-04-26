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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>

#include "syscalls.h"
#include "private.h"
#include "win.h"
#include "linux.h"

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

void print_header(output_format_t format, drakvuf_t drakvuf,
                  bool syscall, const drakvuf_trap_info_t* info,
                  int nr, const char *module, const syscall_t *sc,
                  uint64_t ret, const char *extra_info)
{
    gchar* escaped_pname = NULL;
    const char *name = sc ? sc->name : info->trap->name;
    const char *type = NULL;

    switch (format)
    {
        case OUTPUT_CSV:
            type = syscall ? "syscall" : "sysret";
            printf("%s," FORMAT_TIMEVAL ",%" PRIu32 \
                   ",0x%" PRIx64 ",\"%s\",%d,%d" \
                   ",%s,%" PRIi64 \
                   ",%" PRIi32 ",%s,%s",
                   type, UNPACK_TIMEVAL(info->timestamp), info->vcpu,
                   info->regs->cr3, info->attached_proc_data.name, info->attached_proc_data.pid, info->attached_proc_data.ppid,
                    USERIDSTR(drakvuf), info->attached_proc_data.userid,
                   nr, module, name);
            if ( !syscall )
                printf(",%lu,%s", ret, extra_info);
            break;
        case OUTPUT_KV:
            type = syscall ? "syscall" : "sysret";
            printf("%s Time=" FORMAT_TIMEVAL ",vCPU=%" PRIu32 \
                   ",CR3=0x%" PRIx64 ",ProcessName=\"%s\",PID=%d,PPID=%d" \
                   ",UserName=\"%s\",UserId=%" PRIu64 \
                   ",Syscall=%" PRIi32 ",Module=\"%s\",Method=\"%s\"",
                   type, UNPACK_TIMEVAL(info->timestamp), info->vcpu,
                   info->regs->cr3, info->attached_proc_data.name, info->attached_proc_data.pid, info->attached_proc_data.ppid,
                   USERIDSTR(drakvuf), info->attached_proc_data.userid,
                   nr, module, name);
            if ( !syscall )
                printf(",Ret=%lu,Info=\"%s\"", ret, extra_info?:"");
            break;
        case OUTPUT_JSON:
            // print_footer() puts single EOL at end of JSON doc to simplify parsing on other end
            type = syscall ? "syscall" : "sysret";
            escaped_pname = drakvuf_escape_str(info->attached_proc_data.name);
            printf( "{"
                    "\"Plugin\": \"syscalls\","
                    "\"Type\" : \"%s\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"VCPU\": %" PRIu32 ","
                    "\"CR3\": %" PRIu64 ","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"TID\": %d,"
                    "\"Module\": \"%s\","
                    "\"Method\": \"%s\","
                    "\"Args\": {",
                    type, UNPACK_TIMEVAL(info->timestamp),
                    info->vcpu, info->regs->cr3, escaped_pname,
                    USERIDSTR(drakvuf), info->attached_proc_data.userid,
                    info->attached_proc_data.pid, info->attached_proc_data.ppid, info->attached_proc_data.tid,
                    module, name);

            if ( syscall )
                printf("\"Args\": [");
            else
                printf("\"Ret\": %" PRIu64 ","
                       "\"Info\": \"%s\"",
                        ret, extra_info ?: "");

            g_free(escaped_pname);
            break;

        case OUTPUT_DEFAULT:
        default:
            type = syscall ? "[SYSCALL]" : "[SYSRET]";
            printf("%s TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 \
                   " CR3:0x%" PRIx64 ",\"%s\" PID:%d PPID:%d TID:%d"
                   " %s:%" PRIi64 \
                   " %" PRIi32 ":%s!%s",
                   type, UNPACK_TIMEVAL(info->timestamp), info->vcpu,
                   info->regs->cr3, info->attached_proc_data.name, info->attached_proc_data.pid, info->attached_proc_data.ppid, info->attached_proc_data.tid,
                   USERIDSTR(drakvuf), info->attached_proc_data.userid,
                   nr, module, name);
            if ( !syscall )
                printf(" Ret:%lu Info:%s", ret, extra_info ?: "");
            break;
    }
}

void print_nargs(output_format_t format, uint32_t nargs)
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

void print_args(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscall_t* sc, void* args_data)
{
    if ( !args_data )
        return;

    size_t nargs = sc->num_args;
    uint32_t* args_data32 = (uint32_t*)args_data;
    uint64_t* args_data64 = (uint64_t*)args_data;

    for ( size_t i=0; i<nargs; i++ )
    {
        addr_t val = 0;

        if ( 4 == s->reg_size )
            memcpy(&val, &args_data32[i], sizeof(uint32_t));
        else
            memcpy(&val, &args_data64[i], sizeof(uint64_t));

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

void print_footer(output_format_t format, uint32_t nargs, bool syscall)
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
            // close JSON args object and document
            if ( syscall )
                printf("] } }\n");
            else
                printf("} }\n");
            break;
        default:
        case OUTPUT_DEFAULT:
            if ( nargs == 0 )
                printf("\n");
            break;
    }
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
    ssize_t bytes_read;
    do
    {
        char* line = NULL;
        size_t len = 0;
        bytes_read = getline(&line, &len, f);
        while (bytes_read > 0 && (line[bytes_read - 1] == '\n' || line[bytes_read - 1] == '\r')) bytes_read--;
        if (bytes_read > 0)
        {
            line[bytes_read] = '\0';
            g_hash_table_insert(table, line, NULL);
        }
        else
            free(line);
    } while (bytes_read != -1);

    fclose(f);
    return table;
}

void free_trap(gpointer p)
{
    if ( !p )
        return;

    drakvuf_trap_t *t = (drakvuf_trap_t*)p;
    if ( t->data )
        g_slice_free(struct wrapper, t->data);

    g_slice_free(drakvuf_trap_t, t);
}

syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* c, output_format_t output)
    : traps(NULL)
    , filter(NULL)
    , win32k_json(NULL)
    , format{output}
    , offsets(NULL)
{
    this->os = drakvuf_get_os_type(drakvuf);
    this->kernel_base = drakvuf_get_kernel_base(drakvuf);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->reg_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    this->pm = vmi_get_page_mode(vmi, 0);
    drakvuf_release_vmi(drakvuf);

    if ( c->syscalls_filter_file )
        this->filter = read_syscalls_filter(c->syscalls_filter_file);
    if ( c->win32k_profile )
        this->win32k_json = json_object_from_file(c->win32k_profile);

    if ( this->os == VMI_OS_WINDOWS )
        setup_windows(drakvuf, this);
    else
        setup_linux(drakvuf, this);

    if ( !this->traps )
    {
        PRINT_DEBUG("No traps were added by setup\n");
        throw -1;
    }
}

syscalls::~syscalls()
{
    GSList* loop = this->traps;
    while (loop)
    {
        free_trap(loop->data);
        loop = loop->next;
    }

    if ( this->filter )
        g_hash_table_destroy(this->filter);

    g_free(this->offsets);
    g_slist_free(this->traps);
}
