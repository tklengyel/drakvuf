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
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>

#define PAGE_SHIFT 12
#define PAGE_OFFSET_MASK ((1 << PAGE_SHIFT) - 1)

#ifdef DRAKVUF_DEBUG

extern bool verbose;

#define PRINT_DEBUG(...) \
    do { \
        if(verbose) { \
            eprint_current_time(); \
            fprintf (stderr, __VA_ARGS__); \
        }\
    } while (0)

#else
#define PRINT_DEBUG(...) \
    do {} while(0)
#endif

#define UNUSED(x) (void)(x)

static drakvuf_t drakvuf = {0};
static GSList* traps = NULL;

static addr_t kaslr = 0;
static addr_t kpdb = 0;

// Kernel range
static addr_t stext = 0;
static addr_t etext = 0;

// Track the range of virtual addresses seen
static addr_t    addr_min = 0;
static addr_t    addr_max = 0;

// Max function/data length to account for in sym resolution
#define MAX_SCAN_LEN 0x200

static int resolve_va(vmi_instance_t vmi,
                      addr_t va, const char** sym, size_t* ofs)
{
    int rc = 0;
    const char* osym = NULL;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = kpdb,
        .addr = 0,
    };

    *sym = "unknown";
    *ofs = 0;

    if (va < addr_min || va > addr_max + MAX_SCAN_LEN)
    {
        rc = EINVAL;
        fprintf(stderr, "VA %lx not in range [%lx-%lx]\n", va, addr_min, addr_max);
        goto exit;
    }

    rc = ENOENT;
    for (addr_t a = va; a >= va - MAX_SCAN_LEN; --a)
    {
        osym = vmi_translate_v2ksym(vmi, &ctx, a);
        if (NULL != osym)
        {
            *sym = osym;
            *ofs = va - a;
            rc = 0;
            break;
        }
    }

    if (rc)
    {
        PRINT_DEBUG("No symbol found at/near %lx\n", va);
    }

exit:
    return rc;
}

static event_response_t memaccess_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    event_response_t rsp = 0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    memaccess_type_t access = info->trap->memaccess.access;
    addr_t va = (addr_t)(info->trap->data) + (info->trap_pa & PAGE_OFFSET_MASK);
    const char* sym = NULL;
    size_t ofs = 0;

    (void) resolve_va(vmi, va, &sym, &ofs);

    printf("[MEMACCESS] TIME: " FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:%" PRIx64 " PA %" PRIx64
           " COMM \"%s\" UID %" PRIi64 " VA %" PRIx64 "=%s+%ld access 0x%x=%c%c%c\n",

           UNPACK_TIMEVAL(info->timestamp),
           info->vcpu, info->regs->cr3, info->trap_pa,
           info->proc_data.name, info->proc_data.userid, va, sym, ofs,
           access,
           (access & VMI_MEMACCESS_R) ? 'r' : '-',
           (access & VMI_MEMACCESS_W) ? 'w' : '-',
           (access & VMI_MEMACCESS_X) ? 'x' : '-');

    drakvuf_release_vmi(drakvuf);
    return rsp;
}

static void close_handler(int signal)
{
    drakvuf_interrupt(drakvuf, signal);
}

static void cleanup(void)
{
    GSList* loop = traps;

    fprintf(stderr, "Cleaning up...\n");
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*) loop->data;
        PRINT_DEBUG("Removing trap for VA %lx MFN %lx\n",
                    (unsigned long)trap->data, trap->memaccess.gfn);

        drakvuf_remove_trap(drakvuf, trap, NULL);

        // data, name fields don't hold allocations
        g_free(trap);
        loop = loop->next;
    }
    g_slist_free(traps);
    traps = NULL;
}

static drakvuf_trap_t* create_watchpoint(addr_t va)
{
    drakvuf_trap_t* trap = NULL;
    status_t status = 0;
    addr_t pa = 0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    status = vmi_translate_kv2p(vmi, va, &pa);
    if (VMI_SUCCESS != status)
    {
        fprintf(stderr, "Failed to get PA for VA %lx\n", va);
        goto exit;
    }

    trap = (drakvuf_trap_t*) g_malloc0(sizeof(*trap));
    if (NULL == trap)
    {
        fprintf(stderr, "g_malloc0() failed\n");
        goto exit;
    }

    if (0 == addr_min) addr_min = va;
    if (0 == addr_max) addr_max = va;

    addr_min = MIN(addr_min, va);
    addr_max = MAX(addr_max, va);

    trap->type = MEMACCESS;
    trap->cb   = memaccess_cb;
    trap->data = (void*)va;

    trap->memaccess.gfn    = pa >> PAGE_SHIFT;
    trap->memaccess.access = VMI_MEMACCESS_W;
    trap->memaccess.type   = PRE;

    PRINT_DEBUG("Monitoring kernel VA %lx PA %lx MFN %lx\n",
                va, pa, trap->memaccess.gfn);

    traps = g_slist_prepend(traps, trap);

exit:
    drakvuf_release_vmi(drakvuf);
    return trap;
}


static int init_linux()
{
    int rc = 0;
    symbols_t* symbols = NULL;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    addr_t base = 0;
    addr_t rva = 0;

    if (VMI_SUCCESS != vmi_pid_to_dtb(vmi, 0, &kpdb))
    {
        rc = ENOENT;
        fprintf(stderr, "Couldn't find kernel page table base\n");
        goto exit;
    }

    if ( !drakvuf_get_constant_rva(drakvuf, "_text", &rva) )
    {
        rc = ENOENT;
        fprintf(stderr, "Couldn't find symbol _text\n");
        goto exit;
    }

    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "_stext", &stext))
    {
        rc = ENOENT;
        fprintf(stderr, "Couldn't find symbol _stext\n");
        goto exit;
    }

    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "_etext", &etext))
    {
        rc = ENOENT;
        fprintf(stderr, "Couldn't find symbol _etext\n");
        goto exit;
    }

    base = drakvuf_get_kernel_base(drakvuf);
    kaslr = base - rva;

    PRINT_DEBUG("Linux kernel: VA [%lx - %lx], cr3=%lx, kaslr=%lx\n",
                stext, etext, kpdb, kaslr);

    symbols = drakvuf_get_symbols_from_rekall(drakvuf);
    if (NULL == symbols)
    {
        rc = ENOSPC;
        fprintf(stderr, "Failed to read symbols\n");
        goto exit;
    }

    for (size_t i = 0; i < symbols->count; ++i)
    {
        const struct symbol* s = &symbols->symbols[i];
        addr_t va = kaslr + s->rva;

        PRINT_DEBUG("Adding symbol %s <== %lx\n", s->name, va);
        vmi_rvacache_add(vmi, 0, kpdb, va, s->name);
    }

exit:
    drakvuf_free_symbols(symbols);
    drakvuf_release_vmi(drakvuf);
    return rc;
}

static int register_watchpoints_linux(void)
{
    int rc = 0;

    for (addr_t a = stext; a < etext; a += VMI_PS_4KB)
    {
        drakvuf_trap_t* t = create_watchpoint(a);
        if (NULL == t)
        {
            rc = ENOMEM;
            fprintf(stderr, "Failed to allocate trap\n");
            goto exit;
        }
        if (!drakvuf_add_trap(drakvuf, t))
        {
            rc = EBADE;
            fprintf(stderr, "drakvuf_add_trap() failed\n");
            goto exit;
        }
    }

exit:
    return rc;
}

static int init(void)
{
    int rc = 0;
    os_t os = drakvuf_get_os_type(drakvuf);

    switch (os)
    {
        case VMI_OS_LINUX:
            rc = init_linux();
            if (rc) { goto exit; }

            rc = register_watchpoints_linux();
            if (rc) { goto exit; }

            break;
        default:
            rc = EINVAL;
            fprintf(stderr, "Unhandled OS found\n");
            break;
    }

exit:
    return rc;
}

int main(int argc, char** argv)
{
    int c;
    int rc = 1;
    char* rekall_profile = NULL;
    char* domain = NULL;
    bool libvmi_conf = false;
    bool leave_paused = false;
    bool verbose = false;
    struct sigaction act = {0};
    int long_index = 0;
    const struct option long_opts[] =
    {
        {"rekall-kernel", required_argument, NULL, 'r'},
        {"verbose", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "r:d:lpv";

    if (argc < 4)
    {
        fprintf(stderr, "Required input:\n"
                "\t -r, --rekall-kernel <rekall profile>\n"
                "\t                           The Rekall profile of the OS kernel\n"
                "\t -d <domain ID or name>    The domain's ID or name\n"
                "Optional inputs:\n"
                "\t -l                        Use libvmi.conf\n"
                "\t -p                        Leave domain paused after DRAKVUF exits\n"
#ifdef DRAKVUF_DEBUG
                "\t -v, --verbose             Turn on verbose (debug) output\n"
#endif
               );
        goto exit;
    }

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch (c)
        {
            case 'r':
                rekall_profile = optarg;
                break;
            case 'd':
                domain = optarg;
                break;
            case 'p':
                leave_paused = true;
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = true;
                break;
#endif
            case 'l':
                libvmi_conf = true;
                break;
            default:
                if (isalnum(c))
                    fprintf(stderr, "Unrecognized option: %c\n", c);
                else
                    fprintf(stderr, "Unrecognized option: %s\n", long_opts[long_index].name);
                goto exit;
        }
    }

    if (!domain)
    {
        fprintf(stderr, "No domain name specified (-d)!\n");
        goto exit;
    }

    if (!rekall_profile)
    {
        fprintf(stderr, "No Rekall profile specified (-r)!\n");
        goto exit;
    }

    PRINT_DEBUG("Starting DRAKVUF initialization\n");
    if (!drakvuf_init(&drakvuf, domain, rekall_profile, NULL, verbose, libvmi_conf))
    {
        fprintf(stderr, "drakvuf_init() failed\n");
        goto exit;
    }
    PRINT_DEBUG("DRAKVUF initializated\n");

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
    sigaction(SIGABRT, &act, NULL);

    rc = init();
    if (rc)
    {
        goto exit;
    }

    /* Start the event listener */
    PRINT_DEBUG("Beginning DRAKVUF loop\n");
    drakvuf_loop(drakvuf);
    rc = 0;

    PRINT_DEBUG("Finished DRAKVUF loop\n");

exit:
    cleanup();
    drakvuf_close(drakvuf, leave_paused);
    return rc;
}
