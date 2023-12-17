/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <map>
#include <libdrakvuf/libdrakvuf.h>

/*
 * Structures and functions to store stat data
 */
static std::map<std::pair<vmi_pid_t, uint32_t>, uint64_t> stats;

static event_response_t cr3_cb(__attribute__((unused)) drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto key = std::make_pair(info->proc_data.pid, info->proc_data.tid);
    auto search = stats.find(key);
    if (stats.end() != search)
        ++stats[key];
    else
        stats[key] = 1;

    return VMI_EVENT_RESPONSE_NONE;
}

static drakvuf_t drakvuf = NULL;

static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
}

static bool is_interrupted(drakvuf_t _drakvuf, void*)
{
    return drakvuf_is_interrupted(_drakvuf);
}

int main(int argc, char** argv)
{
    fprintf(stderr, "%s %s v%s Copyright (C) 2014-2023 Tamas K Lengyel\n",
        PACKAGE_NAME, argv[0], PACKAGE_VERSION);

    /* this is the VM that we are looking at */
    if (argc != 5)
    {
        printf("Usage: %s -d <domain name|domain id> -r <profile>\n", argv[0]);
        return 1;
    }

    char* domain;

    if (strcmp(argv[1], "-d")==0)
    {
        domain = argv[2];
    }
    else
    {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    char* profile = NULL;

    if (strcmp(argv[3], "-r") == 0)
    {
        profile = argv[4];
    }
    else
    {
        printf("You have to specify path to profile!\n");
        return 1;
    }

    /* Some local variables */
    drakvuf_trap_t trap;
    trap.type = REGISTER;
    trap.regaccess.type = CR3;
    trap.cb = cr3_cb;
    trap.ttl = UNLIMITED_TTL;
    trap.ah_cb = nullptr;


    /* initialize the Drakvuf library */
    if (!drakvuf_init(&drakvuf, domain, profile, NULL, false, 0, false, UNLIMITED_TTL, NULL, true, false))
    {
        printf("Failed to initialize Drakvuf\n");
        goto done;
    }

    /* for a clean exit */
    struct sigaction act;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if ( !drakvuf_add_trap(drakvuf, &trap) )
    {
        printf("Failed to trap CR3\n");
        goto done;
    }

    drakvuf_loop(drakvuf, is_interrupted, nullptr);

    for (auto k: stats)
        printf("PID:%d,TID:%d,COUNT:%ld\n", k.first.first, k.first.second, k.second);

done:
    drakvuf_resume(drakvuf);
    drakvuf_close(drakvuf, 0);

    return 0;
}
