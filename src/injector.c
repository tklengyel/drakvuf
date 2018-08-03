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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <libvmi/libvmi.h>

#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/libinjector.h>

static drakvuf_t drakvuf;

static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
}

static inline void print_help(void)
{
    fprintf(stderr, "Required input:\n"
            "\t -r <rekall profile>       The Rekall profile of the OS kernel\n"
            "\t -d <domain ID or name>    The domain's ID or name\n"
            "\t -i <injection pid>        The PID of the process to hijack for injection\n"
            "\t -e <inject_file>          The executable to start with injection\n"
            "Optional inputs:\n"
            "\t -m <inject_method>        The injection method (createproc (32 and 64-bit), shellexec, shellcode or doppelganging (Win10) for Windows amd64 only)\n"
            "\t [-B] <path>               The path of the windows binary to inject (requires -m doppelganging)\n"
            "\t [-P] <target>             The path of the clean guest process to use as a cover (requires -m doppelganging)\n"
            "\t -I <injection thread>     The ThreadID in the process to hijack for injection (requires -i)\n"
            "\t -c <current_working_dir>  The current working directory for injected executable\n"
#ifdef DRAKVUF_DEBUG
            "\t -v                        Turn on verbose (debug) output\n"
#endif
           );
}

int main(int argc, char** argv)
{
    int rc = 0;
    vmi_pid_t injection_pid = 0;
    uint32_t injection_thread = 0;
    char c;
    char* rekall_profile = NULL;
    char* domain = NULL;
    char* inject_file = NULL;
    char* inject_cwd = NULL;
    char* binary_path = NULL;
    char* target_process = NULL;
    injection_method_t injection_method = INJECT_METHOD_CREATEPROC;
    bool verbose = 0;

    if (argc < 4)
    {
        print_help();
        return 1;
    }

    while ((c = getopt (argc, argv, "r:d:i:I:e:m:B:P:v")) != -1)
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
                else if (!strncmp(optarg,"createproc",10))
                    injection_method = INJECT_METHOD_CREATEPROC;
                else if (!strncmp(optarg,"shellcode",9))
                    injection_method = INJECT_METHOD_SHELLCODE;
                else if (!strncmp(optarg,"doppelganging",13))
                    injection_method = INJECT_METHOD_DOPP;
                else
                {
                    fprintf(stderr, "Unrecognized injection method\n");
                    return rc;
                }
                break;
            case 'B':
                binary_path = optarg;
                break;
            case 'P':
                target_process = optarg;
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = 1;
                break;
#endif
            default:
                fprintf(stderr, "Unrecognized option: %c\n", c);
                return rc;
        }

    if ( !rekall_profile || !domain || !injection_pid || !inject_file )
    {
        print_help();
        return 1;
    }
    if ( INJECT_METHOD_DOPP == injection_method && (!binary_path || !target_process) )
    {
        print_help();
        return 1;
    }

    /* for a clean exit */
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if (!drakvuf_init(&drakvuf, domain, rekall_profile, verbose))
    {
        fprintf(stderr, "Failed to initialize on domain %s\n", domain);
        return 1;
    }

    printf("Injector starting %s through PID %u TID: %u\n", inject_file, injection_pid, injection_thread);
    int injection_result = injector_start_app(drakvuf, injection_pid, injection_thread, inject_file, inject_cwd, injection_method, OUTPUT_DEFAULT, binary_path, target_process);

    if (injection_result)
        printf("Process startup success\n");
    else
    {
        printf("Process startup failed\n");
        rc = 1;
    }

    drakvuf_close(drakvuf, 0);

    return rc;
}
