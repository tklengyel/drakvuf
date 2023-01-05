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
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <config.h>

#include "../xen_helper/xen_helper.h"

#define CLONE_CMD       "%s %s %u %s"
#define DRAKVUF_CMD     "%s %s %u %u %u %s %s %s %lu"
#define CONFIG_CMD      "%s %s %u %u %u %s %s %s %lu"
#define CLEANUP_CMD     "%s %u %u"
#define TCPDUMP_CMD     "%s %u %s %s %s %lu"

#define UNUSED(x) (void)(x)

struct start_drakvuf
{
    int threadid;
    domid_t cloneID;
    char* input;
    char* clone_name;
    GMutex timer_lock;
    uint32_t timer;
    time_t utime;
};

static GThreadPool* pool;
static const char* domain_name;
static const char* domain_config;
static const char* json_kernel_path;
static const char* in_folder;
static const char* run_folder;
static const char* out_folder;
static const char* clone_script;
static const char* config_script;
static const char* drakvuf_script;
static const char* cleanup_script;
static const char* tcpdump_script;
static uint32_t threads;
static uint32_t injection_pid;
static bool shutting_down;

static GMutex locks[128];

xen_interface_t* xen;

void close_handler(int signal)
{
    shutting_down = signal;
}

static void
make_clone(xen_interface_t* xen, domid_t* cloneID, uint16_t vlan, char** clone_name)
{
    char* command;
    command = g_strdup_printf(CLONE_CMD, clone_script, domain_name, vlan, domain_config);
    printf("** RUNNING COMMAND: %s\n", command);
    char* output = NULL;
    g_spawn_command_line_sync(command, &output, NULL, NULL, NULL);
    g_free(command);
    xen_get_dom_info(xen, output, cloneID, clone_name);
    g_free(output);
}

gpointer tcpdump(gpointer data)
{
    struct start_drakvuf* start = (struct start_drakvuf*)data;
    char* command;
    command = g_strdup_printf(TCPDUMP_CMD, tcpdump_script, start->threadid+1, run_folder, start->input, out_folder, start->utime);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    g_free(command);
    return NULL;
}

static inline int find_thread()
{
    unsigned int i=0;
    for (; i<threads; i++)
    {
        if (g_mutex_trylock(&locks[i]))
            return i;
    }
    return -1;
}

static inline void cleanup(domid_t cloneID, int vlan)
{
    char* command;
    command = g_strdup_printf(CLEANUP_CMD, cleanup_script, cloneID, vlan);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    g_free(command);
}

gpointer timer_thread(gpointer data)
{

    struct start_drakvuf* start = (struct start_drakvuf*)data;

    gboolean gotlock = FALSE;

    while (start->timer > 0)
    {
        gotlock = g_mutex_trylock(&start->timer_lock);
        if ( gotlock )
        {
            g_mutex_unlock(&start->timer_lock);
            break;
        }

        start->timer--;
        sleep(1);
    }

    if ( !gotlock )
        cleanup(start->cloneID, start->threadid+1);

    return NULL;
}

static struct start_drakvuf* prepare(struct start_drakvuf* start, int _threadid)
{
    if (shutting_down)
        return NULL;

    domid_t cloneID = 0;
    char* clone_name = NULL;
    int threadid = start ? start->threadid : _threadid;

    if ( shutting_down )
        return NULL;

    printf("[%i] Making clone\n", threadid);
    make_clone(xen, &cloneID, threadid+1, &clone_name);

    while ((!clone_name || !cloneID) && !shutting_down)
    {
        printf("[%i] Clone creation failed, trying again\n", threadid);
        free(clone_name);
        clone_name = NULL;
        cloneID = 0;

        make_clone(xen, &cloneID, threadid+1, &clone_name);
    }

    if ( shutting_down )
        return NULL;

    //uint64_t shared = xen_memshare(xen, domID, cloneID);
    //printf("Shared %"PRIu64" pages\n", shared);

    if (!start)
    {
        start = g_try_malloc0(sizeof(struct start_drakvuf));
        start->threadid = threadid;
        g_mutex_init(&start->timer_lock);
    }

    start->cloneID = cloneID;
    start->clone_name = clone_name;
    start->utime = time(NULL);

    return start;
}

static inline void start(struct start_drakvuf* start, char* sample)
{
    if ( shutting_down || !start || !sample )
        return;

    start->input = g_strdup(sample);
    g_thread_pool_push(pool, start, NULL);
}

void run_drakvuf(gpointer data, gpointer user_data)
{
    UNUSED(user_data);
    struct start_drakvuf* start = data;
    char* command;
    gint rc;
    GThread* timer;
    GThread* tcpd;

restart:
    command = NULL;
    rc = 0;
    printf("[%i] Starting %s on domid %u\n", start->threadid, start->input, start->cloneID);

    start->timer = 60;
    g_mutex_lock(&start->timer_lock);
    timer = g_thread_new("timer", timer_thread, start);

    command = g_strdup_printf(CONFIG_CMD, config_script, json_kernel_path, start->cloneID, injection_pid, start->threadid+1, run_folder, start->input, out_folder, start->utime);
    printf("[%i] ** RUNNING COMMAND: %s\n", start->threadid, command);
    g_spawn_command_line_sync(command, NULL, NULL, &rc, NULL);
    g_free(command);

    g_mutex_unlock(&start->timer_lock);
    g_thread_join(timer);

    printf("[%i] ** Preconfig finished with RC %i. Timer: %i.\n", start->threadid, rc, start->timer);

    if (!start->timer)
        goto end;

    tcpd = g_thread_new("tcpdump", tcpdump, start);

    start->timer = 180;
    g_mutex_lock(&start->timer_lock);
    timer = g_thread_new("timer", timer_thread, start);

    command = g_strdup_printf(DRAKVUF_CMD, drakvuf_script, json_kernel_path, start->cloneID, injection_pid, start->threadid+1, run_folder, start->input, out_folder, start->utime);
    printf("[%i] ** RUNNING COMMAND: %s\n", start->threadid, command);
    g_spawn_command_line_sync(command, NULL, NULL, &rc, NULL);
    g_free(command);

    g_mutex_unlock(&start->timer_lock);
    g_thread_join(timer);
    g_thread_join(tcpd);

    printf("[%i] ** DRAKVUF finished with RC %i. Timer: %i\n", start->threadid, rc, start->timer);

    if ( start->timer )
    {
        printf("[%i] Finished processing %s\n", start->threadid, start->input);

        g_mutex_unlock(&locks[start->threadid]);
        g_mutex_clear(&start->timer_lock);
        g_free(start->input);
        g_free(start->clone_name);
        g_free(start);
        return;
    }
    else
        cleanup(start->cloneID, start->threadid+1);

end:
    if ( !shutting_down )
    {
        printf("[%i] %s failed to execute on %u because of a timeout, creating new clone\n", start->threadid, start->input, start->cloneID);
        prepare(start, -1);
        goto restart;
    }
}

int main(int argc, char** argv)
{
    DIR* dir;
    struct dirent* ent;
    unsigned int i;
    unsigned int processed = 0;
    unsigned int total_processed = 0;
    int ret = 0;
    struct sigaction act;
    shutting_down = 0;

    fprintf(stderr, "%s %s v%s Copyright (C) 2014-2023 Tamas K Lengyel\n",
        PACKAGE_NAME, argv[0], PACKAGE_VERSION);

    if (argc!=15)
    {
        printf("Not enough arguments: %i!\n", argc);
        printf("%s <loop (0) or poll (1)> <origin domain name> <domain config> <path to kernel json> <injection pid> <watch folder> <serve folder> <output folder> <max clones> <clone_script> <config_script> <drakvuf_script> <cleanup_script> <tcpdump_script>\n", argv[0]);
        return 1;
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    xen_init_interface(&xen);

    int do_poll = atoi(argv[1]);
    domain_name = argv[2];
    domain_config = argv[3];
    json_kernel_path = argv[4];
    injection_pid = atoi(argv[5]);
    in_folder = argv[6];
    run_folder = argv[7];
    out_folder = argv[8];
    threads = atoi(argv[9]);
    clone_script = argv[10];
    config_script = argv[11];
    drakvuf_script = argv[12];
    cleanup_script = argv[13];
    tcpdump_script = argv[14];

    if (threads > 128)
    {
        printf("Too many clones requested (max 128 is specified right now)\n");
        return 1;
    }

    for (i=0; i<threads; i++)
        g_mutex_init(&locks[i]);

    pool = g_thread_pool_new(run_drakvuf, NULL, threads, TRUE, NULL);

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, in_folder, IN_CLOSE_WRITE);
    char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

    struct pollfd pollfd =
    {
        .fd = fd,
        .events = POLLIN
    };

    int threadid = -1;

    do
    {
        processed = 0;

        while (threadid<0 && !shutting_down)
        {
            sleep(1);
            threadid = find_thread();
        }

        if ((dir = opendir (in_folder)) != NULL)
        {
            while ((ent = readdir (dir)) != NULL && !shutting_down)
            {
                if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                    continue;

                char* command;
                command = g_strdup_printf("mv %s/%s %s/%s", in_folder, ent->d_name, run_folder, ent->d_name);
                printf("** MOVING FILE FOR PROCESSING: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                g_free(command);

                struct start_drakvuf* _start = prepare(NULL, threadid);
                start(_start, ent->d_name);

                threadid = -1;
                processed++;

            }
            closedir (dir);
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
            printf("Batch processing started %u samples (total %u)\n", processed, total_processed);
        }

        if ( !processed && !shutting_down )
        {
            if ( do_poll )
            {
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
                } while (!shutting_down && !ret);
            }
            else
                sleep(1);
        }
    } while (!shutting_down && !ret);

    inotify_rm_watch( fd, wd );
    close(fd);

    g_thread_pool_free(pool, FALSE, TRUE);

    if ( threadid >= 0 )
        g_mutex_unlock(&locks[threadid]);

    for (i=0; i<threads; i++)
        g_mutex_clear(&locks[i]);

    xen_free_interface(xen);

    printf("Finished processing %u samples\n", total_processed);
    return ret;
}
