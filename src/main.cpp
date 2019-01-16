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
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <exception>

#include "drakvuf.h"

static drakvuf_c* drakvuf;

void close_handler(int signal)
{
    drakvuf->interrupt(signal);
}

static inline void disable_plugin(char* optarg, bool* plugin_list)
{
    for (int i=0; i<__DRAKVUF_PLUGIN_LIST_MAX; i++)
        if (!strcmp(optarg, drakvuf_plugin_names[i]))
            plugin_list[i] = false;
}

int main(int argc, char** argv)
{
    int c, rc = 1, timeout = 0;
    char const* inject_file = nullptr;
    char const* inject_cwd = nullptr;
    injection_method_t injection_method = INJECT_METHOD_CREATEPROC;
    char* domain = nullptr;
    char* rekall_profile = nullptr;
    char* dump_folder = nullptr;
    char* tcpip = nullptr;
    char* binary_path = nullptr;
    char* target_process = nullptr;
    vmi_pid_t injection_pid = -1;
    uint32_t injection_thread = 0;
    struct sigaction act;
    output_format_t output = OUTPUT_DEFAULT;
    bool plugin_list[] = {[0 ... __DRAKVUF_PLUGIN_LIST_MAX-1] = 1};
    bool verbose = false;
    bool cpuid_stealth = false;
    bool leave_paused = false;
    char const* syscalls_filter_file = nullptr;
    bool dump_modified_files = false;
    bool filedelete_use_injector = false;
    bool abort_on_bsod = false;
    bool libvmi_conf = false;

    eprint_current_time();
    fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);

    if ( __DRAKVUF_PLUGIN_LIST_MAX == 0 )
    {
        eprint_current_time();
        fprintf(stderr, "No plugins have been enabled, nothing to do!\n");
        return rc;
    }

    if (argc < 4)
    {
        fprintf(stderr, "Required input:\n"
                "\t -r, --rekall-kernel <rekall profile>\n"
                "\t                           The Rekall profile of the OS kernel\n"
                "\t -d <domain ID or name>    The domain's ID or name\n"
                "Optional inputs:\n"
                "\t -l                        Use libvmi.conf\n"
                "\t -i <injection pid>        The PID of the process to hijack for injection\n"
                "\t -I <injection thread>     The ThreadID in the process to hijack for injection (requires -i)\n"
                "\t -e <inject_file>          The executable to start with injection\n"
                "\t -c <current_working_dir>  The current working directory for injected executable\n"
                "\t -m <inject_method>        The injection method: createproc, shellexec, shellcode, doppelganging\n"
                "\t -t <timeout>              Timeout (in seconds)\n"
                "\t -o <format>               Output format (default or csv)\n"
                "\t -x <plugin>               Don't activate the specified plugin\n"
                "\t -p                        Leave domain paused after DRAKVUF exits\n"
#ifdef ENABLE_DOPPELGANGING
                "\t -B <path>                 The host path of the windows binary to inject (requires -m doppelganging)\n"
                "\t -P <target>               The guest path of the clean guest process to use as a cover (requires -m doppelganging)\n"
#endif
#ifdef ENABLE_PLUGIN_FILEDELETE
                "\t -D <file dump folder>     Folder where extracted files should be stored at\n"
                "\t -M                        Dump new or modified files also (requires -D)\n"
                "\t -n                        Use extraction method based on function injection (requires -D)\n"
#endif
#ifdef ENABLE_PLUGIN_SOCKETMON
                "\t -T, --rekall-tcpip <rekall profile>\n"
                "\t                           The Rekall profile for tcpip.sys\n"
#endif
#ifdef ENABLE_PLUGIN_CPUIDMON
                "\t -s                        Hide Hypervisor bits and signature in CPUID\n"
#endif
#ifdef DRAKVUF_DEBUG
                "\t -v, --verbose             Turn on verbose (debug) output\n"
#endif
#ifdef ENABLE_PLUGIN_SYSCALLS
                "\t -S <syscalls filter>      File with list of syscalls for trap in syscalls plugin (trap all if parameter is absent)\n"
#endif
#ifdef ENABLE_PLUGIN_BSODMON
                "\t -b                        Exit from execution as soon as a BSoD is detected\n"
#endif
               );
        return rc;
    }

    int long_index = 0;
    const option long_opts[] =
    {
        {"rekall-kernel", optional_argument, NULL, 'r'},
        {"rekall-tcpip", optional_argument, NULL, 'T'},
        {"verbose", no_argument, NULL, 'v'},
    };
    const char* opts = "r:d:i:I:e:m:t:D:o:vx:spT:S:Mc:nbl";

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        switch (c)
        {
            case 'r':
                rekall_profile = optarg;
                break;
            case 'd':
                domain = optarg;
                break;
            case 'i':
                injection_pid = atoi(optarg);
                break;
            case 'I':
                injection_thread = atoi(optarg);
                break;
            case 'e':
                inject_file = optarg;
                break;
            case 'c':
                inject_cwd = optarg;
                break;
            case 'm':
                if (!strncmp(optarg,"shellexec",9))
                    injection_method = INJECT_METHOD_SHELLEXEC;
                if (!strncmp(optarg,"createproc",10))
                    injection_method = INJECT_METHOD_CREATEPROC;
                if (!strncmp(optarg,"shellcode",9))
                    injection_method = INJECT_METHOD_SHELLCODE;
                if (!strncmp(optarg,"doppelganging",13))
#ifdef ENABLE_DOPPELGANGING
                    injection_method = INJECT_METHOD_DOPP;
#else
                {
                    fprintf(stderr, "Doppelganging is not available, you need to re-run ./configure!\n");
                    return rc;
                }
#endif
                break;
#ifdef ENABLE_DOPPELGANGING
            case 'B':
                binary_path = optarg;
                break;
            case 'P':
                target_process = optarg;
                break;
#endif
            case 't':
                timeout = atoi(optarg);
                break;
            case 'D':
                dump_folder = optarg;
                break;
            case 'o':
                if (!strncmp(optarg,"csv",3))
                    output = OUTPUT_CSV;
                if (!strncmp(optarg,"kv",2))
                    output = OUTPUT_KV;
                break;
            case 'x':
                disable_plugin(optarg, plugin_list);
                break;
            case 's':
                cpuid_stealth = true;
                break;
            case 'p':
                leave_paused = true;
                break;
            case 'T':
                tcpip = optarg;
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = true;
                break;
#endif
            case 'S':
                syscalls_filter_file = optarg;
                break;
            case 'M':
                dump_modified_files = true;
                break;
            case 'n':
                filedelete_use_injector = true;
                break;
            case 'b':
                abort_on_bsod = true;
                break;
            case 'l':
                libvmi_conf = true;
                break;
            default:
                if (isalnum(c))
                    fprintf(stderr, "Unrecognized option: %c\n", c);
                else
                    fprintf(stderr, "Unrecognized option: %s\n", long_opts[long_index].name);
                return rc;
        }

    if (!domain)
    {
        fprintf(stderr, "No domain name specified (-d)!\n");
        return rc;
    }

    if (!rekall_profile)
    {
        fprintf(stderr, "No Rekall profile specified (-r)!\n");
        return rc;
    }

    if ( INJECT_METHOD_DOPP == injection_method && (!binary_path || !target_process) )
    {
        fprintf(stderr, "Missing parameters for process doppelganging injection (-B and -P)!\n");
        return rc;
    }

    PRINT_DEBUG("Starting DRAKVUF initialization\n");

    try
    {
        drakvuf = new drakvuf_c(domain, rekall_profile, output, timeout, verbose, leave_paused, libvmi_conf);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Failed to initialize DRAKVUF: %s\n", e.what());
        return rc;
    }

    PRINT_DEBUG("DRAKVUF initializated\n");

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, nullptr);
    sigaction(SIGTERM, &act, nullptr);
    sigaction(SIGINT, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);

    if ( injection_pid > 0 && inject_file )
    {
        PRINT_DEBUG("Starting injection with PID %i(%i) for %s\n", injection_pid, injection_thread, inject_file);
        int ret = drakvuf->inject_cmd(injection_pid, injection_thread, inject_file, inject_cwd, injection_method, output, binary_path, target_process);
        if (!ret)
            goto exit;
    }

    PRINT_DEBUG("Starting plugins\n");

    if ( drakvuf->start_plugins(plugin_list, dump_folder, dump_modified_files, filedelete_use_injector, cpuid_stealth, tcpip, syscalls_filter_file, abort_on_bsod) < 0 )
        goto exit;

    PRINT_DEBUG("Beginning DRAKVUF loop\n");

    /* Start the event listener */
    drakvuf->loop();
    rc = 0;

    PRINT_DEBUG("Finished DRAKVUF loop\n");

exit:
    delete drakvuf;
    return rc;
}
