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

#include "drakvuf.h"

static gpointer timer(gpointer data)
{
    drakvuf_c* drakvuf = (drakvuf_c*)data;

    /* Wait for the loop to start */
    g_mutex_lock(&drakvuf->loop_signal);
    g_mutex_unlock(&drakvuf->loop_signal);

    while (drakvuf->timeout && !drakvuf->interrupted)
    {
        sleep(1);
        --drakvuf->timeout;
    }

    if (!drakvuf->interrupted)
    {
        drakvuf->interrupt(-1);
    }

    g_thread_exit(NULL);
    return NULL;
}

int drakvuf_c::start_plugins(const bool* plugin_list,
                             const char* dump_folder,          // PLUGIN_FILEDELETE
                             bool dump_modified_files,         // PLUGIN_FILEDELETE
                             bool filedelete_use_injector,     // PLUGIN_FILEDELETE
                             bool cpuid_stealth,               // PLUGIN_CPUIDMON
                             const char* tcpip_profile,        // PLUGIN_SOCKETMON
                             const char* syscalls_filter_file, // PLUGIN_SYSCALLS
                             bool abort_on_bsod )              // PLUGIN_BSODMON
{
    int i, rc;

    for (i=0; i<__DRAKVUF_PLUGIN_LIST_MAX; i++)
    {
        if (plugin_list[i])
        {
            switch ((drakvuf_plugin_t)i)
            {
                case PLUGIN_FILEDELETE:
                {
                    struct filedelete_config c =
                    {
                        .dump_folder = dump_folder,
                        .dump_modified_files = dump_modified_files,
                        .filedelete_use_injector = filedelete_use_injector,
                    };

                    rc = this->plugins->start((drakvuf_plugin_t)i, &c);
                    break;
                }

                case PLUGIN_CPUIDMON:
                    rc = this->plugins->start((drakvuf_plugin_t)i, &cpuid_stealth);
                    break;

                case PLUGIN_SOCKETMON:
                {
                    struct socketmon_config c =
                    {
                        .tcpip_profile = tcpip_profile,
                        .tcpip_profile_json = json_object_from_file(tcpip_profile)
                    };
                    rc = this->plugins->start((drakvuf_plugin_t)i, &c);
                    break;
                }

                case PLUGIN_SYSCALLS:
                {
                    struct syscalls_config c =
                    {
                        .syscalls_filter_file = syscalls_filter_file
                    };
                    rc = this->plugins->start((drakvuf_plugin_t)i, &c);
                    break;
                }

                case PLUGIN_BSODMON:
                    rc = this->plugins->start((drakvuf_plugin_t)i, &abort_on_bsod);
                    break;

                default:
                    rc = this->plugins->start((drakvuf_plugin_t)i, NULL);
                    break;
            };

            if ( rc < 0 )
                return rc;
        }
    }

    return 1;
}

drakvuf_c::drakvuf_c(const char* domain,
                     const char* rekall_profile,
                     const output_format_t output,
                     const int timeout,
                     const bool verbose,
                     const bool leave_paused)
{
    this->drakvuf = NULL;
    this->interrupted = 0;
    this->timeout = timeout;
    this->process_start_timeout = timeout;
    this->leave_paused = leave_paused;
    this->process_start_detected = 0;

    if (!drakvuf_init(&this->drakvuf, domain, rekall_profile, verbose))
        throw -1;

    this->os = drakvuf_get_os_type(this->drakvuf);

    g_mutex_init(&this->loop_signal);
    g_mutex_lock(&this->loop_signal);
    g_mutex_init(&this->loop_signal2);
    g_mutex_lock(&this->loop_signal2);

    if (timeout > 0)
        this->timeout_thread = g_thread_new(NULL, timer, (void*)this);

    this->plugins = new drakvuf_plugins(this->drakvuf, output, this->os);
}

drakvuf_c::~drakvuf_c()
{
    if ( !this->interrupted )
        this->interrupt(-1);

    g_mutex_trylock(&this->loop_signal);
    g_mutex_unlock(&this->loop_signal);
    g_mutex_clear(&this->loop_signal);
    g_mutex_trylock(&this->loop_signal2);
    g_mutex_unlock(&this->loop_signal2);
    g_mutex_clear(&this->loop_signal2);

    if (this->drakvuf)
        drakvuf_close(this->drakvuf, this->leave_paused);

    if (this->plugins)
        delete this->plugins;

    if (this->timeout_thread)
        g_thread_join(this->timeout_thread);
}

void drakvuf_c::interrupt(int signal)
{
    this->interrupted = signal;
    drakvuf_interrupt(this->drakvuf, signal);
}

void drakvuf_c::loop()
{
    this->interrupted = 0;
    g_mutex_unlock(&this->loop_signal);
    drakvuf_loop(this->drakvuf);
}

void drakvuf_c::pause()
{
    drakvuf_pause(this->drakvuf);
}

void drakvuf_c::resume()
{
    drakvuf_resume(this->drakvuf);
}

int drakvuf_c::inject_cmd(vmi_pid_t injection_pid, uint32_t injection_tid, const char* inject_cmd, const char* cwd, injection_method_t method, output_format_t format, const char* binary_path, const char* target_process, bool wait_for_process)
{
    int rc = 0;
    this->injector = injector_start_app(this->drakvuf, injection_pid, injection_tid, inject_cmd, cwd, method, format, binary_path, target_process, wait_for_process, &rc);

    if (!rc)
        fprintf(stderr, "Process startup failed\n");
    return rc;
}

void drakvuf_c::inject_cmd_cleanup(void)
{
    injector_cleanup(this->injector);
}
