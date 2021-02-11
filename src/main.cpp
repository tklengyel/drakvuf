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
#include <memory>

#include "drakvuf.h"
#include "exitcodes.h"

static std::unique_ptr<drakvuf_c> drakvuf;

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

static inline void disable_all_plugins(bool* plugin_list)
{
    for (int i = 0; i < __DRAKVUF_PLUGIN_LIST_MAX; i++)
        plugin_list[i] = false;
}

static inline void enable_plugin(char* optarg, bool* plugin_list, bool* disabled_all)
{
    if (!*disabled_all)
    {
        disable_all_plugins(plugin_list);
        *disabled_all = true;
    }
    for (int i = 0; i < __DRAKVUF_PLUGIN_LIST_MAX; i++)
        if (!strcmp(optarg, drakvuf_plugin_names[i]))
            plugin_list[i] = true;
}

static void print_usage()
{
    fprintf(stderr, "Required input:\n"
            "\t -r, --json-kernel <path to json>\n"
            "\t                           The OS kernel's json profile\n"
            "\t -d <domain ID or name>    The domain's ID or name\n"
            "Optional inputs:\n"
            "\t -l                        Use libvmi.conf\n"
            "\t -k <kpgd value>           Use provided KPGD value for faster and more robust startup (advanced)\n"
            "\t -i <injection pid>        The PID of the process to hijack for injection\n"
            "\t -I <injection thread>     The ThreadID in the process to hijack for injection (requires -i)\n"
            "\t -e <inject_file>          The executable to start with injection\n"
            "\t -c <current_working_dir>  The current working directory for injected executable\n"
            "\t -m <inject_method>        The injection method: [WIN]  : createproc, shellexec, shellcode, doppelganging\n"
            "\t                                               : [LINUX]: execproc -> execlp(), linuxshellcode \n"
            "\t -f <args for exec>        Additional args for exec() (requires -m execproc)\n"
            "\t -g                        Search required for injection functions in all processes\n"
            "\t -j, --injection-timeout <seconds>\n"
            "\t                           Injection timeout (in seconds, 0 == no timeout)\n"
            "\t --terminate               Terminate injected process\n"
            "\t --termination-timeout     Timeout to wait for process termination (in seconds)\n"
            "\t -t <timeout>              Timeout (in seconds)\n"
            "\t -o <format>               Output format (default, csv, kv, or json)\n"
            "\t -x <plugin>               Don't activate the specified plugin\n"
            "\t --wait-stop-plugins <timeout>\n"
            "\t                           Wait for plugins to stop before termination loop\n"
            "\t -a <plugin>               Activate the specified plugin\n"
            "\t -p                        Leave domain paused after DRAKVUF exits\n"
            "\t -F                        Enable fast singlestepping (requires Xen 4.14+)\n"
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
            "\t -T, --json-tcpip <path to json>\n"
            "\t                           The JSON profile for tcpip.sys\n"
#endif
#ifdef ENABLE_PLUGIN_CPUIDMON
            "\t -s                        Hide Hypervisor bits and signature in CPUID\n"
#endif
#ifdef DRAKVUF_DEBUG
            "\t -v, --verbose             Turn on verbose (debug) output\n"
#endif
#ifdef ENABLE_PLUGIN_SYSCALLS
            "\t -S, --syscall-hooks-list <syscalls filter>\n"
            "\t                           File with list of syscalls for trap in syscalls plugin (trap all if parameter is absent)\n"
            "\t --disable-sysret          Do not monitor syscall results\n"
#endif
#ifdef ENABLE_PLUGIN_BSODMON
            "\t -b                        Exit from execution as soon as a BSoD is detected\n"
#endif
            "\t -w, --json-wow <path to json>\n"
            "\t                           The JSON profile for WoW64 NTDLL\n"
#ifdef ENABLE_PLUGIN_CLIPBOARDMON
            "\t -W, --json-win32k <path to json>\n"
            "\t                           The JSON profile for win32k.sys\n"
#endif
            "\t --json-sspicli <path to json>\n"
            "\t                           The JSON profile for sspicli.dll\n"
            "\t --json-kernel32 <path to json>\n"
            "\t                           The JSON profile for kernel32.dll\n"
            "\t --json-kernelbase <path to json>\n"
            "\t                           The JSON profile for KernelBase.dll\n"
            "\t --json-wow-kernel32 <path to json>\n"
            "\t                           The JSON profile for SysWOW64/kernel32.dll\n"
            "\t --json-ntdll <path to json>\n"
            "\t                           The JSON profile for ntdll.dll\n"
            "\t --json-iphlpapi <path to json>\n"
            "\t                           The JSON profile for iphlpapi.dll\n"
#ifdef ENABLE_PLUGIN_WMIMON
            "\t --json-mpr <path to json>\n"
            "\t                           The JSON profile for mpr.dll\n"
            "\t --json-ole32 <path to json>\n"
            "\t                           The JSON profile for ole32.dll\n"
            "\t --json-wow-ole32 <path to json>\n"
            "\t                           The JSON profile for SysWOW64/ole32.dll\n"
            "\t --json-combase <path to json>\n"
            "\t                           The JSON profile for combase.dll\n"
#endif
#ifdef ENABLE_PLUGIN_MEMDUMP
            "\t --memdump-dir <directory>\n"
            "\t                           Where to store memory dumps\n"
            "\t --json-clr <path to json>\n"
            "\t                           The JSON profile for clr.dll\n"
            "\t --json-mscorwks <path to json>\n"
            "\t                           The JSON profile for mscorewks.dll\n"
#endif
#if defined(ENABLE_PLUGIN_MEMDUMP) || defined(ENABLE_PLUGIN_APIMON)
            "\t --dll-hooks-list <file>\n"
            "\t                           List of DLL functions to be hooked (see wiki)\n"
            "\t --userhook-no-addr\n"
            "\t                           Stop printing addresses of string arguments in apimon and memdump\n"
#endif
#ifdef ENABLE_PLUGIN_PROCDUMP
            "\t --procdump-dir <directory>\n"
            "\t                           Where to store processes dumps\n"
            "\t --compress-procdumps\n"
            "\t                           Controls compression of processes dumps on disk\n"
#endif
#ifdef ENABLE_PLUGIN_HYPERBEE
            "\t --hyperbee-dump-dir <directory>\n"
            "\t                           Folder where to store page/vad dumps (path)\n"
            "\t --hyperbee-filter-executable <filename>\n"
            "\t                           Limit the output to events regarding this file\n"

#endif
            "\t -h, --help                Show this help\n"
           );
}

int main(int argc, char** argv)
{
    int c;
    int timeout = 0;
    char const* inject_file = nullptr;
    char const* inject_cwd = nullptr;
    injection_method_t injection_method = INJECT_METHOD_CREATEPROC;
    int injection_timeout = 0;
    bool injection_global_search = false;
    char* domain = nullptr;
    char* json_kernel_path = nullptr;
    char* json_wow_path = nullptr;
    char* binary_path = nullptr;
    char* target_process = nullptr;
    vmi_pid_t injection_pid = -1;
    uint32_t injection_thread = 0;
    struct sigaction act;
    output_format_t output = OUTPUT_DEFAULT;
    bool plugin_list[] = {[0 ... __DRAKVUF_PLUGIN_LIST_MAX-1] = 1};
    int wait_stop_plugins = 0;
    bool verbose = false;
    bool leave_paused = false;
    bool libvmi_conf = false;
    bool fast_singlestep = false;
    addr_t kpgd = 0;
    auto terminated_processes = std::make_shared<std::unordered_map<vmi_pid_t, bool>>();
    plugins_options options = { .terminated_processes = terminated_processes };
    bool disabled_all = false; // Used to disable all plugin once
    const char* args[10] = {};
    int args_count = 0;
    bool terminate = false;
    int termination_timeout = 20;

    eprint_current_time();

    fprintf(stderr, "%s v%s Copyright (C) 2014-2021 Tamas K Lengyel\n",
            PACKAGE_NAME, PACKAGE_VERSION);

    if ( __DRAKVUF_PLUGIN_LIST_MAX == 0 )
    {
        eprint_current_time();
        fprintf(stderr, "No plugins have been enabled, nothing to do!\n");
        return drakvuf_exit_code_t::FAIL;
    }

    int long_index = 0;
    enum
    {
        opt_json_sspicli = 1000,
        opt_json_kernel32,
        opt_json_kernelbase,
        opt_json_wow_kernel32,
        opt_json_ntdll,
        opt_json_iphlpapi,
        opt_json_mpr,
        opt_json_ole32,
        opt_json_wow_ole32,
        opt_json_combase,
        opt_memdump_dir,
        opt_dll_hooks_list,
        opt_procdump_dir,
        opt_compress_procdumps,
        opt_json_clr,
        opt_json_mscorwks,
        opt_disable_sysret,
        opt_userhook_no_addr,
        opt_terminate,
        opt_termination_timeout,
        opt_wait_stop_plugins,
        opt_hyperbee_dump_dir,
        opt_hyperbee_filter_executable,
    };
    const option long_opts[] =
    {
        {"json-kernel", required_argument, NULL, 'r'},
        {"json-kernel32", required_argument, NULL, opt_json_kernel32},
        {"json-kernelbase", required_argument, NULL, opt_json_kernelbase},
        {"json-sspicli", required_argument, NULL, opt_json_sspicli},
        {"json-tcpip", required_argument, NULL, 'T'},
        {"json-win32k", required_argument, NULL, 'W'},
        {"json-wow", required_argument, NULL, 'w'},
        {"json-wow-kernel32", required_argument, NULL, opt_json_wow_kernel32},
        {"json-ntdll", required_argument, NULL, opt_json_ntdll},
        {"json-iphlpapi", required_argument, NULL, opt_json_iphlpapi},
        {"json-mpr", required_argument, NULL, opt_json_mpr},
        {"injection-timeout", required_argument, NULL, 'j'},
        {"terminate", no_argument, NULL, opt_terminate},
        {"termination-timeout", required_argument, NULL, opt_termination_timeout},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"json-ole32", required_argument, NULL, opt_json_ole32},
        {"json-wow-ole32", required_argument, NULL, opt_json_wow_ole32},
        {"json-combase", required_argument, NULL, opt_json_combase},
        {"memdump-dir", required_argument, NULL, opt_memdump_dir},
        {"dll-hooks-list", required_argument, NULL, opt_dll_hooks_list},
        {"procdump-dir", required_argument, NULL, opt_procdump_dir},
        {"compress-procdumps", no_argument, NULL, opt_compress_procdumps},
        {"json-clr", required_argument, NULL, opt_json_clr},
        {"json-mscorwks", required_argument, NULL, opt_json_mscorwks},
        {"syscall-hooks-list", required_argument, NULL, 'S'},
        {"disable-sysret", no_argument, NULL, opt_disable_sysret},
        {"userhook-no-addr", no_argument, NULL, opt_userhook_no_addr},
        {"fast-singlestep", no_argument, NULL, 'F'},
        {"wait-stop-plugins", required_argument, NULL, opt_wait_stop_plugins},
        {"hyperbee-dump-dir", required_argument, NULL, opt_hyperbee_dump_dir},
        {"hyperbee-filter-executable", required_argument, NULL, opt_hyperbee_filter_executable},



        {NULL, 0, NULL, 0}
    };
    const char* opts = "r:d:i:I:e:m:t:D:o:vx:a:f:spT:S:Mc:nblgj:k:w:W:hF";

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        switch (c)
        {
            case 'r':
                json_kernel_path = optarg;
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
            case 'g':
                injection_global_search = true;
                break;
            case 'j':
                injection_timeout = atoi(optarg);
                break;
            case opt_terminate:
                terminate = true;
                break;
            case opt_termination_timeout:
                termination_timeout = atoi(optarg);
                break;
            case 'm':
                if (!strncmp(optarg, "shellexec", 9))
                    injection_method = INJECT_METHOD_SHELLEXEC;
                if (!strncmp(optarg, "createproc", 10))
                    injection_method = INJECT_METHOD_CREATEPROC;
                if (!strncmp(optarg, "shellcode", 9))
                    injection_method = INJECT_METHOD_SHELLCODE;
                if (!strncmp(optarg, "doppelganging", 13))
#ifdef ENABLE_DOPPELGANGING
                    injection_method = INJECT_METHOD_DOPP;
#else
                {
                    fprintf(stderr, "Doppelganging is not available, you need to re-run ./configure!\n");
                    return drakvuf_exit_code_t::FAIL;
                }
#endif
                if (!strncmp(optarg, "execproc", 8))
                    injection_method = INJECT_METHOD_EXECPROC;
                if (!strncmp(optarg, "linuxshellcode", 14))
                    injection_method = INJECT_METHOD_SHELLCODE_LINUX;
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
                options.dump_folder = optarg;
                break;
            case 'o':
                if (!strncmp(optarg, "csv", 3))
                    output = OUTPUT_CSV;
                if (!strncmp(optarg, "kv", 2))
                    output = OUTPUT_KV;
                if (!strncmp(optarg, "json", 4))
                    output = OUTPUT_JSON;
                break;
            case 'x':
                disable_plugin(optarg, plugin_list);
                break;
            case opt_wait_stop_plugins:
                wait_stop_plugins = atoi(optarg);
                break;
            case 'a':
                enable_plugin(optarg, plugin_list, &disabled_all);
                break;
            case 'f':
                args[args_count] = optarg;
                args_count++;
                break;
            case 's':
                options.cpuid_stealth = true;
                break;
            case 'p':
                leave_paused = true;
                break;
            case 'T':
                options.tcpip_profile = optarg;
                break;
            case 'W':
                options.win32k_profile = optarg;
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = true;
                break;
#endif
#ifdef ENABLE_PLUGIN_SYSCALLS
            case 'S':
                options.syscalls_filter_file = optarg;
                break;
            case opt_disable_sysret:
                options.disable_sysret = true;
                break;
#endif
            case 'M':
                options.dump_modified_files = true;
                break;
            case 'n':
                options.filedelete_use_injector = true;
                break;
            case 'b':
                options.abort_on_bsod = true;
                break;
            case 'l':
                libvmi_conf = true;
                break;
            case 'F':
                fast_singlestep = true;
                break;
            case 'k':
                kpgd = strtoull(optarg, NULL, 0);
                break;
            case 'w':
                json_wow_path = optarg;
                break;
            case opt_json_sspicli:
                options.sspicli_profile = optarg;
                break;
            case opt_json_kernel32:
                options.kernel32_profile = optarg;
                break;
            case opt_json_kernelbase:
                options.kernelbase_profile = optarg;
                break;
            case opt_json_wow_kernel32:
                options.wow_kernel32_profile = optarg;
                break;
            case opt_json_ntdll:
                options.ntdll_profile = optarg;
                break;
            case opt_json_iphlpapi:
                options.iphlpapi_profile = optarg;
                break;
            case opt_json_mpr:
                options.mpr_profile = optarg;
                break;
            case opt_userhook_no_addr:
                options.userhook_no_addr = true;
                break;
#ifdef ENABLE_PLUGIN_WMIMON
            case opt_json_ole32:
                options.ole32_profile = optarg;
                break;
            case opt_json_wow_ole32:
                options.wow_ole32_profile = optarg;
                break;
            case opt_json_combase:
                options.combase_profile = optarg;
                break;
#endif
#ifdef ENABLE_PLUGIN_MEMDUMP
            case opt_memdump_dir:
                options.memdump_dir = optarg;
                break;
            case opt_dll_hooks_list:
                options.dll_hooks_list = optarg;
                break;
            case opt_json_clr:
                options.clr_profile = optarg;
                break;
            case opt_json_mscorwks:
                options.mscorwks_profile = optarg;
                break;
#endif
#ifdef ENABLE_PLUGIN_PROCDUMP
            case opt_procdump_dir:
                options.procdump_dir = optarg;
                break;
            case opt_compress_procdumps:
                options.compress_procdumps = true;
                break;
#endif
#ifdef ENABLE_PLUGIN_HYPERBEE
            case opt_hyperbee_dump_dir:
                options.hyperbee_dump_dir = optarg;
                break;
            case opt_hyperbee_filter_executable:
                options.hyperbee_filter_executable = optarg;
                break;
#endif
            case 'h':
                print_usage();
                return drakvuf_exit_code_t::SUCCESS;
            default:
                if (isalnum(c))
                    fprintf(stderr, "Unrecognized option: %c\n", c);
                else
                    fprintf(stderr, "Unrecognized option: %s\n", long_opts[long_index].name);
                return drakvuf_exit_code_t::FAIL;
        }

    if (!domain)
    {
        fprintf(stderr, "No domain name specified (-d)!\n");
        return drakvuf_exit_code_t::FAIL;
    }

    if (!json_kernel_path)
    {
        fprintf(stderr, "No kernel JSON profile specified (-r)!\n");
        return drakvuf_exit_code_t::FAIL;
    }

    if (INJECT_METHOD_DOPP == injection_method && (!binary_path || !target_process))
    {
        fprintf(stderr, "Missing parameters for process doppelganging injection (-B and -P)!\n");
        return drakvuf_exit_code_t::FAIL;
    }

    PRINT_DEBUG("Starting DRAKVUF initialization\n");

    try
    {
        drakvuf = std::make_unique<drakvuf_c>(domain, json_kernel_path, json_wow_path, output, verbose, leave_paused, libvmi_conf, kpgd, fast_singlestep);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Failed to initialize DRAKVUF: %s\n", e.what());
        return drakvuf_exit_code_t::FAIL;
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

    vmi_pid_t injected_pid = 0;
    if (injection_pid > 0 && inject_file)
    {
        PRINT_DEBUG("Starting injection with PID %i(%i) for %s\n", injection_pid, injection_thread, inject_file);
        injector_status_t ret = drakvuf->inject_cmd(injection_pid, injection_thread, inject_file, inject_cwd, injection_method, output, binary_path, target_process, injection_timeout, injection_global_search, args_count, args, &injected_pid);
        switch (ret)
        {
            case INJECTOR_FAILED_WITH_ERROR_CODE:
                return drakvuf_exit_code_t::INJECTION_UNSUCCESSFUL;
            case INJECTOR_FAILED:
                return drakvuf_exit_code_t::INJECTION_ERROR;
            case INJECTOR_SUCCEEDED:
                break;
            case INJECTOR_TIMEOUTED:
                return drakvuf_exit_code_t::INJECTION_TIMEOUT;
        }
    }

    PRINT_DEBUG("Starting plugins\n");

    if (drakvuf->start_plugins(plugin_list, &options) < 0)
        return drakvuf_exit_code_t::FAIL;

    PRINT_DEBUG("Beginning DRAKVUF main loop\n");

    /* Start the event listener */
    drakvuf->loop(timeout);

    PRINT_DEBUG("Finished DRAKVUF main loop\n");

    switch (drakvuf->is_interrupted())
    {
        case SIGDRAKVUFKERNELPANIC:
            return drakvuf_exit_code_t::KERNEL_PANIC;
        default:
            break;
    }

    PRINT_DEBUG("Beginning stop plugins\n");

    bool plugins_pending = false;
    int rc = drakvuf->stop_plugins(plugin_list);
    if (rc < 0)
        return drakvuf_exit_code_t::FAIL;
    else if (rc > 0)
        plugins_pending = true;

    PRINT_DEBUG("Finished stop plugins\n");

    if (plugins_pending && wait_stop_plugins)
    {
        PRINT_DEBUG("Beginning wait stop plugins\n");

        drakvuf->plugin_stop_loop(wait_stop_plugins, plugin_list);

        PRINT_DEBUG("Finished wait stop plugins\n");
    }

    if (terminate && injected_pid)
        drakvuf->terminate(injection_pid, injection_thread, injected_pid, termination_timeout, terminated_processes);

    return drakvuf_exit_code_t::SUCCESS;
}
