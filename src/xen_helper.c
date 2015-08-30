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

#include <xenctrl.h>
#include <libxl_utils.h>

#include "xen_helper.h"

bool xen_init_interface(xen_interface_t **xen) {

    *xen = g_malloc0(sizeof(xen_interface_t));

    /* We create an xc interface to test connection to it */
    (*xen)->xc = xc_interface_open(0, 0, 0);

    if ((*xen)->xc == NULL) {
        fprintf(stderr, "xc_interface_open() failed!\n");
        xen_free_interface(*xen);
        return 0;
    }

    /* We don't need this at the moment, but just in case */
    //xen->xsh=xs_open(XS_OPEN_READONLY);
    (*xen)->xl_logger = (xentoollog_logger *) xtl_createlogger_stdiostream(
            stderr, XTL_PROGRESS, 0);

    if (!(*xen)->xl_logger)
        return 0;

    if (0
            != libxl_ctx_alloc(&(*xen)->xl_ctx, LIBXL_VERSION, 0,
                    (*xen)->xl_logger)) {
        fprintf(stderr, "libxl_ctx_alloc() failed!\n");
        xen_free_interface(*xen);
        return 0;
    }

    return 1;
}

void xen_free_interface(xen_interface_t* xen) {
    if (xen) {
        if (xen->xl_ctx)
            libxl_ctx_free(xen->xl_ctx);
        if (xen->xl_logger)
            xtl_logger_destroy(xen->xl_logger);
        //if (xen->xsh) xs_close(xen->xsh);
        if (xen->xc)
            xc_interface_close(xen->xc);
        free(xen);
    }
}

int get_dom_info(xen_interface_t *xen, const char *input, uint32_t *domID,
        char **name) {

    uint32_t _domID = INVALID_DOMID;
    char *_name = NULL;

    sscanf(input, "%u", &_domID);

    if (_domID == INVALID_DOMID) {
        _name = strdup(input);
        libxl_name_to_domid(xen->xl_ctx, input, &_domID);
        if (!_domID || _domID == INVALID_DOMID) {
            printf("Domain is not running, failed to get domID from name!\n");
            free(_name);
            return -1;
        } else {
            //printf("Got domID from name: %u\n", _domID);
        }
    } else {
        //printf("Converting domid %u to name\n", _domID);
        _name = libxl_domid_to_name(xen->xl_ctx, _domID);
        if (_name == NULL) {
            printf(
                    "Failed to get domain name from ID, is the domain running?\n");
            return -1;
        } else {
            //printf("Got name from domID: %s\n", _name);
        }
    }

    *name = _name;
    *domID = _domID;

    return 1;
}

uint64_t xen_memshare(xen_interface_t *xen, uint32_t domID, uint32_t cloneID) {

    uint64_t shared = 0;

#if __XEN_INTERFACE_VERSION__ < 0x00040600
    uint64_t page, max_page = xc_domain_maximum_gpfn(xen->xc, domID);
#else
    xen_pfn_t page, max_page;
    if (xc_domain_maximum_gpfn(xen->xc, domID, &max_page)) {
        printf("Failed to get max gpfn from Xen!\n");
        goto done;
    }
#endif

    if (!max_page) {
        printf("Failed to get max gpfn!\n");
        goto done;
    }

    if (xc_memshr_control(xen->xc, domID, 1)) {
        printf("Failed to enable memsharing on origin!\n");
        goto done;
    }
    if (xc_memshr_control(xen->xc, cloneID, 1)) {
        printf("Failed to enable memsharing on clone!\n");
        goto done;
    }

    /*
     * page will underflow when done
     */
    for (page = max_page; page <= max_page; page--) {
        uint64_t shandle, chandle;

        if (xc_memshr_nominate_gfn(xen->xc, domID, page, &shandle))
            continue;
        if (xc_memshr_nominate_gfn(xen->xc, cloneID, page, &chandle))
            continue;
        if (xc_memshr_share_gfns(xen->xc, domID, page, shandle, cloneID, page,
            chandle))
            continue;

        shared++;
    }

    done: return shared;
}

void print_sharing_info(xen_interface_t *xen, uint32_t domID) {

    xc_dominfo_t info;
    xc_domain_getinfo(xen->xc, domID, 1, &info);

    printf("Shared memory pages: %lu\n", info.nr_shared_pages);
}

/*
 * DomU Configuration management stuff
 */
xen_domconfig_raw_t* xen_domconfig_raw_by_id(xen_interface_t *xen,
        unsigned int domID) {

    xen_domconfig_raw_t *config = malloc(sizeof(xen_domconfig_raw_t));
    config->config_data = NULL;

    if (libxl_userdata_retrieve(xen->xl_ctx, domID, "xl",
	    &(config->config_data), &(config->config_length)))
    {
        printf("Unable to get config file\n");
        free(config);
        return NULL;
    }

    return config;
}

void xen_free_domconfig_raw(xen_domconfig_raw_t* raw_config) {
    g_free(raw_config->config_data);
    free(raw_config);
}
