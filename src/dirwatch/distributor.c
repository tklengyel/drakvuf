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
 * software.  Please contact tamas@tklengyel.com with any such             *
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

/*
 * Take files from <in folder> and place them into folders under <queue folder>.
 * Folders in <queue folder> need to be in a format <queue_name>_<queue_capacity>,
 * such as "testqueue_10". This will result in the distributor placing 10 files
 * into that folder before looking at the next queue (if any).
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>
#include <time.h>
#include <poll.h>

static const char* in_folder;
static const char* queue_folder;

int main(int argc, char** argv)
{
    DIR* indir;
    DIR* qdir;
    struct dirent* inent;
    struct dirent* qdent;
    uint64_t processed = 0;
    uint64_t total_processed = 0;
    uint64_t jobs = 0;
    int ret = 0;
    uint64_t limit = 0;

    if (argc < 3)
    {
        printf("Not enough arguments: %i!\n", argc);
        printf("%s <in folder> <queue folder> <optional limit>\n", argv[0]);
        return 1;
    }

    in_folder = argv[1];
    queue_folder = argv[2];

    if ( argc == 4 )
        limit = strtoull(argv[3], 0, 10);

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, in_folder, IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE);
    char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

    struct pollfd pollfd =
    {
        .fd = fd,
        .events = POLLIN
    };

    do
    {
        jobs = 0;
        processed = 0;

        if ((indir = opendir (in_folder)) != NULL)
        {
            while ((inent = readdir (indir)) != NULL)
            {
                if (!strcmp(inent->d_name, ".") || !strcmp(inent->d_name, ".."))
                    continue;

                jobs++;

                if ((qdir = opendir (queue_folder)) != NULL)
                {
                    while ((qdent = readdir (qdir)) != NULL)
                    {
                        if (!strcmp(qdent->d_name, ".") || !strcmp(qdent->d_name, ".."))
                            continue;

                        if ( !g_strrstr(qdent->d_name, "_") )
                            continue;

                        gchar** qinfo = g_strsplit(qdent->d_name, "_", 2);
                        int qsize = atoi(qinfo[1]);
                        int count = -1;
                        DIR* q;
                        struct dirent* qent;

                        char* folder = g_malloc0(snprintf(NULL, 0, "%s/%s", queue_folder, qdent->d_name) + 1);
                        sprintf(folder, "%s/%s", queue_folder, qdent->d_name);

                        if ((q = opendir (folder)) != NULL)
                        {
                            count = 0;
                            while ((qent = readdir (q)) != NULL)
                                if ( strcmp(qent->d_name, ".") && strcmp(qent->d_name, "..") )
                                    count++;
                            closedir (q);
                        }

                        g_free(folder);

                        if ( count >= 0 && qsize >= 0 && qsize > count )
                        {
                            char* command = g_malloc0(snprintf(NULL, 0, "mv %s/%s %s/%s/%s", in_folder, inent->d_name, queue_folder, qdent->d_name, inent->d_name) + 1);
                            sprintf(command, "mv %s/%s %s/%s/%s", in_folder, inent->d_name, queue_folder, qdent->d_name, inent->d_name);
                            printf("** MOVING FILE FOR PROCESSING: %s\n", command);
                            g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                            g_free(command);

                            g_strfreev(qinfo);
                            processed++;
                            break;
                        }

                        g_strfreev(qinfo);
                    }

                    closedir(qdir);
                }
            }
            closedir (indir);
        }
        else
        {
            printf("Failed to open target folder!\n");
            ret = 1;
            break;
        }

        if ( processed )
        {
            total_processed += processed;
            printf("Distributed %lu samples (total %lu)\n", processed, total_processed);

            if ( limit != 0 && total_processed >= limit )
                break;
        }

        if ( !jobs )
        {
            printf("In folder is empty, waiting for file creation\n");

            do
            {
                int rv = poll (&pollfd, 1, 1000);
                if ( rv < 0 )
                {
                    printf("Error polling\n");
                    ret = 1;
                    break;
                }
                if ( rv > 0 && pollfd.revents & POLLIN )
                {
                    if ( read( fd, buffer, sizeof(struct inotify_event) + NAME_MAX + 1 ) < 0 )
                    {
                        printf("Error reading inotify event\n");
                        ret = 1;
                    }
                    break;
                }
            }
            while (!ret);
        }
        else if ( processed != jobs )
            sleep(1);

    }
    while (!ret);

    inotify_rm_watch( fd, wd );
    close(fd);

    printf("Finished processing %lu samples\n", total_processed);
    return ret;
}
