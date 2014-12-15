/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "structures.h"
#include "injector.h"
#include "vmi.h"
#include "pooltag.h"
#include "xen_helper.h"
#include "win-symbols.h"
#include "xmlrpc_client.h"

#define CLONE "../tools/clone.pl"

static honeymon_t _honeymon;
static honeymon_honeypot_t _origin;
static honeymon_clone_t _clone;

static void close_handler(int sig) {
    _clone.interrupted = sig;
}

static void make_clone(xen_interface_t *xen, const char *dom, uint32_t *cloneID,
        uint16_t vlan, char **clone_name) {
    char *command = g_malloc0(snprintf(NULL, 0, "%s %s %u", CLONE, dom, vlan) + 1);
    sprintf(command, "%s %s %u", CLONE, dom, vlan);
    printf("** RUNNING COMMAND: %s\n", command);
    char *output = NULL;
    g_spawn_command_line_sync(command, &output, NULL, NULL, NULL);
    free(command);

    get_dom_info(xen, output, cloneID, clone_name);

    free(output);
}

static void memshare(honeymon_clone_t *clone) {

    if (clone->origin->domID == INVALID_DOMID)
        return;

    uint64_t page = xc_domain_maximum_gpfn(clone->honeymon->xen->xc,
            clone->domID);

    if (page == 0) {
        printf("Failed to get max gpfn!\n");
        return;
    }

    uint64_t shared = 0;
    for (; page > 0; page--) {
        if (!g_hash_table_lookup(clone->page_lookup, &page)) {
            if (xen_memshare(clone->honeymon->xen, clone->origin->domID,
                    clone->domID, page)) {
                shared++;
            }
        } else {
            printf("Skipping page %lu from memory sharing\n", page);
        }
    }

    printf("Shared %lu pages\n", shared);
}

static int init_origin(honeymon_honeypot_t *origin) {
    origin->sym_config = get_all_symbols(origin->rekall_profile);
    if(!origin->sym_config) {
        printf("Error getting rekall symbols\n");
        return 1;
    }

    origin->sym_config->name = "ntoskrnl.exe";
    return 0;
}

static void free_origin(honeymon_honeypot_t *origin) {
    if (origin->sym_config) {
        uint32_t i = 0;
        for (; i < origin->sym_config->sym_count; i++) {
            free(origin->sym_config->syms[i].name);
        }
        free(origin->sym_config->syms);
        free(origin->sym_config);
    }
}

int main(int argc, char** argv) {

    printf("%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);

    if (argc < 4) {
        printf("To start on existing domain:"
               "  %s -d <rekall profile> <domid> [injection pid] [injection executable path]\n",
               argv[0]);
        printf("To create clone domain:"
               " %s -c <rekall profile> <origin> <vlan> [injection pid] [injection executable path]\n",
               argv[0]);
        return 1;
    }

    memset(&_honeymon, 0, sizeof(honeymon_t));
    memset(&_origin, 0, sizeof(honeymon_honeypot_t));
    memset(&_clone, 0, sizeof(honeymon_clone_t));

    _clone.honeymon = &_honeymon;
    _clone.origin = &_origin;

    xen_init_interface(&_honeymon.xen);

    pooltag_build_tree(&_honeymon);
    //vmi_build_guid_tree(&honeymon);

    if (!strcmp(argv[1], "-c")) {

        get_dom_info(_honeymon.xen, argv[3], &_origin.domID, &_origin.name);

        if (!_origin.name || _origin.domID == INVALID_DOMID) {
            printf("Origin domain is not running!\n");
            return 1;
        }

        _clone.vlan = atoi(argv[4]);
        make_clone(_honeymon.xen, _origin.name, &_clone.domID, _clone.vlan, &_clone.clone_name);

        memshare(&_clone);

        honeybrid_client_init();
        _clone.honeybridID = honeybrid_add_clone(_clone.vlan);

        printf("Clone created with name %s domID %u\n", _clone.clone_name,
                _clone.domID);
    }

    if (!strcmp(argv[1], "-d")) {
        _origin.domID = INVALID_DOMID;
        get_dom_info(_honeymon.xen, argv[3], &_clone.domID, &_clone.clone_name);
    }

    _origin.rekall_profile = argv[2];
    if (init_origin(&_origin) == 1) {
        goto exit;
    }

    clone_vmi_init(&_clone);

    if (!_clone.vmi) {
        goto exit;
    }

    vmi_pid_t pid = -1;
    char *app = NULL;
    if (argc == 6) {
        pid = atoi(argv[4]);
        app = argv[5];
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

    if (pid > 0 && app) {
        int rc = start_app(&_clone, pid, app);

        if (!rc) {
            printf("Process startup failed\n");
            goto exit;
        }
    }

    inject_traps(&_clone);

    pthread_t clone_thread;
    pthread_create(&clone_thread, NULL, clone_vmi_thread, (void*) &_clone);
    pthread_join(clone_thread, NULL);

    close_vmi_clone(&_clone);

exit:
    free_origin(&_origin);
    xen_free_interface(_honeymon.xen);
    g_tree_destroy(_honeymon.pooltags);

    if (!strcmp(argv[1], "-c")) {
        honeybrid_remove_clone(_clone.honeybridID);
        honeybrid_client_finish();
    }
    return 0;
}
