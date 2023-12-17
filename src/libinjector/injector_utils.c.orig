/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include "injector_utils.h"

#include <assert.h>

event_response_t override_step(base_injector_t injector, const injector_step_t step, event_response_t event)
{
    injector->step_override = true;
    injector->step = step;
    return event;
}

void fall_through_step(base_injector_t injector, const injector_step_t step)
{
    injector->step = step;
}

// One could not set all registers at once because the kernel structures could be affected.
// For example on Windows 7 x64 GS BASE stores pointer to KPCR. If save
// GS BASE on vCPU0 and start injections Windows scheduler could switch
// thread to other vCPU1. After restoring all registers vCPU1's GS BASE
// would point to KPCR of vCPU0.
// Hence, the safe way is to only modify the general purpose registers
// which won't affect the kernel structures
event_response_t handle_gprs_registers(drakvuf_t drakvuf, drakvuf_trap_info_t* info, base_injector_t injector, event_response_t event)
{
    if (injector->set_gprs_only && event == VMI_EVENT_RESPONSE_SET_REGISTERS)
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        registers_t regs;
        vmi_get_vcpuregs(vmi, &regs, info->vcpu);
        drakvuf_release_vmi(drakvuf);

        copy_gprs(&regs.x86, info->regs);
        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return VMI_EVENT_RESPONSE_NONE;
    }

    return event;
}

static gchar* kv_strescape(const gchar* str)
{
    const char hexdig[] = "0123456789ABCDEF";
    size_t len = strlen(str);
    gchar* ret = g_malloc0(len * 4 + 3);
    if (!ret) return NULL;
    size_t ret_pos = 0;
    ret[ret_pos++] = '"';
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char c = str[i];
        switch (c)
        {
            case '\r':
                ret[ret_pos++] = '\\';
                ret[ret_pos++] = 'r';
                break;
            case '\n':
                ret[ret_pos++] = '\\';
                ret[ret_pos++] = 'n';
                break;
            case '"':
                ret[ret_pos++] = '\\';
                ret[ret_pos++] = '"';
                break;
            default:
                if (c < ' ')
                {
                    ret[ret_pos++] = '\\';
                    ret[ret_pos++] = 'x';
                    ret[ret_pos++] = hexdig[c >> 4];
                    ret[ret_pos++] = hexdig[c & 0xF];
                }
                else
                    ret[ret_pos++] = c;
                break;
        }
    }
    ret[ret_pos++] = '"';
    return ret;
}

void print_injection_info(
    output_format_t format,
    injection_method_t injector_method,
    inject_result_t injector_result,
    uint32_t target_pid,
    uint32_t pid,
    uint32_t tid,
    const char* process_name,
    const char* arguments,
    const injection_error_t* error
)
{
    const char* method = injection_method_name(injector_method);
    gint64 t = g_get_real_time();

    switch (injector_result)
    {
        case INJECT_RESULT_SUCCESS:
            switch (format)
            {
                case OUTPUT_CSV:
                {
                    gchar* escaped_arguments = drakvuf_escape_str(arguments);
                    printf("inject," FORMAT_TIMEVAL ",%s,Success,%u,\"%s\",%s,%u,%u\n",
                        UNPACK_TIMEVAL(t), method, target_pid, process_name, escaped_arguments, pid, tid);
                    g_free(escaped_arguments);
                    break;
                }

                case OUTPUT_KV:
                {
                    gchar* escaped_process_name = kv_strescape(process_name);
                    gchar* escaped_arguments = kv_strescape(arguments);
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Success,PID=%u,ProcessName=%s,Arguments=%s,InjectedPid=%u,InjectedTid=%u\n",
                        UNPACK_TIMEVAL(t), method, target_pid, escaped_process_name, escaped_arguments, pid, tid);
                    g_free(escaped_process_name);
                    g_free(escaped_arguments);
                    break;
                }

                case OUTPUT_JSON:
                {
                    gchar* escaped_process_name = drakvuf_escape_str(process_name);
                    gchar* escaped_arguments = drakvuf_escape_str(arguments);
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Method\": \"%s\", "
                        "\"Status\": \"Success\", "
                        "\"ProcessName\": %s, "
                        "\"Arguments\": %s, "
                        "\"InjectedPid\": %d, "
                        "\"InjectedTid\": %d"
                        "}\n",
                        UNPACK_TIMEVAL(t), method, escaped_process_name, escaped_arguments, pid, tid);
                    g_free(escaped_process_name);
                    g_free(escaped_arguments);
                    break;
                }

                default:
                case OUTPUT_DEFAULT:
                {
                    gchar* escaped_arguments = drakvuf_escape_str(arguments);
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:SUCCESS PID:%u FILE:\"%s\" ARGUMENTS:%s INJECTED_PID:%u INJECTED_TID:%u\n",
                        UNPACK_TIMEVAL(t), method, target_pid, process_name, escaped_arguments, pid, tid);
                    g_free(escaped_arguments);
                    break;
                }
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
            assert(error);
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",%s,Error,%d,\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, error->code, error->string);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Method=%s,Status=Error,ErrorCode=%d,Error=\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, error->code, error->string);
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
                        UNPACK_TIMEVAL(t), method, error->code, error->string);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " METHOD:%s STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                        UNPACK_TIMEVAL(t), method, error->code, error->string);
                    break;
            }
            break;

        case INJECT_RESULT_METHOD_UNSUPPORTED:
            assert(0);
            break;
    }
}
