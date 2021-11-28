/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include "win_utils.h"

unicode_string_t* convert_utf8_to_utf16(char const* str)
{
    if (!str) return NULL;

    unicode_string_t us =
    {
        .contents = (uint8_t*)g_strdup(str),
        .length = strlen(str),
        .encoding = "UTF-8",
    };

    if (!us.contents) return NULL;

    unicode_string_t* out = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
    if (!out)
    {
        g_free(us.contents);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(&us, out, "UTF-16LE");
    g_free(us.contents);

    if (VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

bool load_file_to_memory(addr_t* output, size_t* size, const char* file)
{
    if (!output || !size || !file)
        return false;

    long payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
    {
        fprintf(stderr, "Could not open file\n");
        return false;
    }

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    if ( (payload_size = ftell (fp)) < 0 )
    {
        fprintf(stderr, "File length error\n");
        fclose(fp);
        return false;
    }
    rewind (fp);

    data = g_try_malloc0(payload_size);
    if ( !data )
    {
        fprintf(stderr, "Could not allocate memory\n");
        fclose(fp);
        return false;
    }

    if ( (size_t)payload_size != fread(data, 1, payload_size, fp) )
    {
        fprintf(stderr, "Could not read file\n");
        g_free(data);
        fclose(fp);
        return false;
    }

    *output = (addr_t)data;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", payload_size);

    fclose(fp);

    return true;
}

bool module_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* ctx )
{
    struct module_context* data = (struct module_context*)ctx;

    if (module_info->base_addr != data->module_addr)
        return false;

    data->addr = drakvuf_exportsym_to_va(drakvuf, module_info->eprocess_addr, data->lib, data->fun);
    if (data->addr)
        return true;

    return false;
}

addr_t get_function_va(drakvuf_t drakvuf, addr_t eprocess_base, char const* lib, char const* fun, bool global_search)
{
    // First check current process for function
    addr_t addr = drakvuf_exportsym_to_va(drakvuf, eprocess_base, lib, fun);
    if (addr)
        return addr;

    // If function is not mapped into the processes address space search it in other processes
    struct module_context module_ctx =
    {
        .lib = lib,
        .fun = fun,
        .addr = 0
    };

    if (global_search)
    {
        // First get modules load address to search for other process with same address
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_PID;

        addr_t module_list_head;
        if (drakvuf_get_process_pid(drakvuf, eprocess_base, &ctx.pid) &&
            drakvuf_get_module_list(drakvuf, eprocess_base, &module_list_head) &&
            drakvuf_get_module_base_addr_ctx(drakvuf, module_list_head, &ctx, lib, &module_ctx.module_addr))
        {
            drakvuf_enumerate_processes_with_module(drakvuf, lib, module_visitor, &module_ctx);
        }
    }

    if (!module_ctx.addr)
        PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);

    return module_ctx.addr;
}

void free_memtraps(injector_t injector)
{
    GSList* loop = injector->memtraps;
    injector->memtraps = NULL;

    while (loop)
    {
        drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)free);
        loop = loop->next;
    }
    g_slist_free(loop);
}

void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    free_memtraps(injector);

    vmi_free_unicode_str(injector->target_file_us);
    vmi_free_unicode_str(injector->cwd_us);
    vmi_free_unicode_str(injector->expanded_target);

    g_free((void*)injector->binary);
    g_free((void*)injector->payload);
    g_free((void*)injector);
}

void injector_free_win(injector_t injector)
{
    free_injector(injector);
}

void print_injection_info(output_format_t format, const char* file, injector_t injector)
{
    static const char* inject_methods_win[] =
    {
        [INJECT_METHOD_CREATEPROC] = "CreateProc",
        [INJECT_METHOD_TERMINATEPROC] = "TerminateProc",
        [INJECT_METHOD_SHELLEXEC] = "ShellExec",
        [INJECT_METHOD_SHELLCODE] = "Shellcode",
        [INJECT_METHOD_READ_FILE] = "ReadFile",
        [INJECT_METHOD_WRITE_FILE] = "WriteFile",
    };

    gint64 t = g_get_real_time();

    const char* process_name = "";
    const char* arguments = "";

    const char* splitter = " ";
    const char* begin_proc_name = file;

    const char* method = inject_methods_win[injector->method];

    if (file[0] == '"')
    {
        splitter = "\"";
        begin_proc_name = &file[1];
    }

    char** split_results = g_strsplit_set(begin_proc_name, splitter, 2);
    char** split_results_iterator = split_results;

    if (*split_results_iterator)
    {
        // Advance iterator to step over image/process name
        process_name = *(split_results_iterator++);
    }

    if (*split_results_iterator)
    {
        arguments = *(split_results_iterator++);
        while (*arguments == ' ')
            arguments++;
    }

    if (injector->expanded_target && injector->expanded_target->contents)
        process_name = (const char*)injector->expanded_target->contents;

    char* escaped_pname = g_strescape(process_name, NULL);
    char* escaped_arguments = g_strescape(arguments, NULL);

    switch (injector->result)
    {
        case INJECT_RESULT_SUCCESS:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,Success,%u,\"%s\",\"%s\",%u,%u\n",
                        UNPACK_TIMEVAL(t), method, injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Success,PID=%u,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                        UNPACK_TIMEVAL(t), method, injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"Success\", "
                        "\"ProcessName\": \"%s\", "
                        "\"Arguments\": \"%s\", "
                        "\"InjectedPid\": %d, "
                        "\"InjectedTid\": %d"
                        "}\n",
                        UNPACK_TIMEVAL(t), method, escaped_pname, escaped_arguments, injector->pid, injector->tid);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s  STATUS:SUCCESS PID:%u FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                        UNPACK_TIMEVAL(t), method, injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;
            }
            break;
        case INJECT_RESULT_TIMEOUT:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,Timeout\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Timeout\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"Timeout\""
                        "}\n", UNPACK_TIMEVAL(t), method);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:Timeout\n", UNPACK_TIMEVAL(t), method);
                    break;
            }
            break;
        case INJECT_RESULT_CRASH:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,Crash\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Crash\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"Crash\""
                        "}\n", UNPACK_TIMEVAL(t), method);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD: %s STATUS:Crash\n", UNPACK_TIMEVAL(t), method);
                    break;
            }
            break;
        case INJECT_RESULT_PREMATURE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,PrematureBreak\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=PrematureBreak\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"PrematureBreak\""
                        "}\n", UNPACK_TIMEVAL(t), method);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:PrematureBreak\n", UNPACK_TIMEVAL(t), method);
                    break;
            }
            break;
        case INJECT_RESULT_INIT_FAIL:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,InitFail\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=InitFail\n", UNPACK_TIMEVAL(t), method);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"InitFail\""
                        "}\n", UNPACK_TIMEVAL(t), method);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:InitFail\n", UNPACK_TIMEVAL(t), method);
                    break;
            }
            break;
        case INJECT_RESULT_ERROR_CODE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,Error,%d,\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Error,ErrorCode=%d,Error=\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"Error\", "
                        "\"ErrorCode\": %d, "
                        "\"Error\": \"%s\""
                        "}\n",
                        UNPACK_TIMEVAL(t), method, injector->error_code.code, injector->error_code.string);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, injector->error_code.code, injector->error_code.string);
                    break;
            }
            break;
    }

    g_free(escaped_pname);
    g_free(escaped_arguments);
    g_strfreev(split_results);
}
