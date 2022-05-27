/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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
 *                                                                         *
 * This file - named hiddump.c - was written by Jan Gruber.                *
 * It is distributed as part of DRAKVUF under the same license and serve   *
 * as a utility to record HID events for later playback inside a guest VM. *
 *                                                                         *
 * To compile it, use the following command                                *
 *       gcc -o hiddump hiddump.c -lX11                                    *
 *                                                                         *
 * To run it, use the following command                                    *
 *       ./hiddump [-h] [-e /dev/input/eventX] [file]                      *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <glib/gprintf.h>

/* Input event codes */
#include <linux/input.h>

/* Needed for retrieval display dimensions */
#include <X11/Xlib.h>

#define FIND_EVENT_FILE_CMD "cat /proc/bus/input/devices | grep mouse\0" //head -n1 | cut -d' ' -f3
#define DEVICE_PATH_STUB "/dev/input/\0"
#define MAX_EVENT_FILES 5
#define POLL_TIMEOUT 1

/* Defines the dword magic number for the resulting binary output file
 *
 * Construction of file's magic number:
 * Take string 'DRAK' (0x44 0x52 0x41 0x4b) and add 0x80 to each char
 *   0x4452414b + 0x80808080
 * = 0xc4d2c1cb <- probably unique, with high bit set on each byte
 */
#define DRAK_MAGIC_NUMBER 0xc4d2c1cb

/* Stop condition */
static volatile sig_atomic_t is_stopping = 0;

/* Signal handler callback */
static void handle_signal(int signum)
{
    is_stopping = 1;
    fprintf(stderr, "Received signal %d - stopping\n", signum);
}

/* Sets callbacks for incoming signals to ensure clean shutdown */
static int install_signal_handler(const int signum)
{
    struct sigaction act;

    memset(&act, 0, sizeof act);
    sigemptyset(&act.sa_mask);
    act.sa_handler = handle_signal;
    act.sa_flags = 0;
    if (sigaction(signum, &act, NULL) == -1)
        return errno;

    return 0;
}

/* Finds event file to retrieve mouse events */
int find_event_file(char** file)
{
    FILE* fp;
    char result[0x100];

    /* Opens the command for reading. */
    fp = popen(FIND_EVENT_FILE_CMD, "r");

    if (fp == NULL)
    {
        fprintf(stderr, "Failed to run command to find event file\n");
        return 1;
    }
    char* pos = NULL;

    /* Reads the output a line at a time - output it. */
    while (fgets(result, sizeof(result), fp) != NULL)
    {
        pos = strstr(result, "event");
        if (!pos)
            continue;
    }

    /* Terminates process */
    pclose(fp);

    if (pos)
    {
        /* Removes ' \n' from end of line */
        if ( strlen(pos) >= 2 )
            pos[strlen(pos) - 2] = '\0';
        *file = g_strdup_printf("/dev/input/%s", pos);
        return 0;
    }
    return 1;
}

/* Retrieves display dimensions */
int get_dimensions(unsigned int* w, unsigned int* h)
{
    Display* display;

    /* Gets connection to X11 display server */
    if ((display = XOpenDisplay(NULL)) == NULL )
    {
        return 1;
    }
    unsigned int ujunk;
    int junk;
    Window wjunk;

    /* Get the root window size */
    int ret = XGetGeometry(display, XDefaultRootWindow(display),
            &wjunk, &junk, &junk, w, h, &ujunk, &ujunk);

    XCloseDisplay(display);

    return ret?0:1;
}

int center_cursor(unsigned int width, unsigned int height)
{
    Display* display;
    Window root_window;

    /* Gets connection to X11 display server */
    if ((display = XOpenDisplay(NULL)) == NULL)
    {
        return 1;
    }
    root_window = XRootWindow(display, 0);

    /* Moves cursor */
    if (XWarpPointer(display, None, root_window, 0, 0, 0, 0, width / 2, height / 2) == 0)
        return 1;

    /* Flushes the output buffer to update the cursor's position */
    XFlush(display);

    XCloseDisplay(display);
    return 0;
}


void write_file_header(FILE* f)
{
    /* Writes 3 dwords as file header
     *
     * 0xcb 0xc1 0xd2 0xc4 == Magic number
     * 0x44 0x52 0x41 0x4b == 'DRAK'
     * 0x00 0x01 0x00 0x00 ==  version 0.1
     */
    int magic = DRAK_MAGIC_NUMBER;
    fwrite(&magic, sizeof(magic), 1, f);

    u_int32_t drak= 0x4b415244;
    fwrite(&drak, sizeof(drak), 1, f); // don't write null byte

    u_int32_t i = 0x00000001;
    fwrite(&i, sizeof(i), 1, f);
}

int store_event(struct timeval* rel_t, unsigned short* type, unsigned short* code, int* val, FILE* fout)
{
    int cnt = 0;
    cnt += fwrite(rel_t, sizeof(struct timeval), 1, fout);
    cnt += fwrite(type, sizeof(unsigned short), 1, fout);
    cnt += fwrite(code, sizeof(unsigned short), 1, fout);
    cnt += fwrite(val, sizeof(int), 1, fout);
    return cnt;
}

int normalize(int value, double factor)
{
    int res;
    double d = factor * (double)value;

    if (value < 0)
    {
        res = (int)(d - 0.5);
    }
    else
        res = (int)(d + 0.5);

    return res;
}

int poll_events(struct pollfd* fds, size_t n, FILE* fout, int seconds, double x_factor, double y_factor)
{
    struct timeval t1, t2, rel_t, end_t;

    /* Sets time frame to record */
    if (seconds > 0)
    {
        gettimeofday(&end_t, NULL);
        end_t.tv_sec += seconds;
    }
    else
    {
        end_t.tv_sec = seconds;
        end_t.tv_usec = 0;
    }

    /* Sets start time, all timestamps are relative to t1 */
    gettimeofday(&t1, NULL);

    /* Received event */
    struct input_event ie;

    int val = 0;
    int ret = -1;
    int nr = 0;
    /* Loops until time is up or SIGINT or SIGTERM is received */
    while (!is_stopping)
    {
        ret = poll(fds, n, POLL_TIMEOUT);

        if (ret == -1)
        {
            fprintf(stderr, "Poll failed: %s.\n", strerror(errno));
            return 1;
        }

        /* Loops over polled pollfd structs */
        for (size_t i = 0; i < n; i++)
        {
            /* Checks, if theres data to read */
            if (fds[i].revents & POLLIN)
            {
                nr = read(fds[i].fd, &ie, sizeof(struct input_event));

                if (nr != sizeof(struct input_event))
                    continue;

                timersub(&ie.time, &t1, &rel_t);

                /* Handles mouse movements */
                if (ie.type == EV_REL)
                {
                    switch (ie.code)
                    {
                        /* Remap for screen size independence */
                        case REL_X:
                            val = normalize(ie.value, x_factor);
                            fprintf(stderr, "%ld.%06ld: REL_X %d\n", rel_t.tv_sec, rel_t.tv_usec, val);
                            break;

                        case REL_Y:
                            val = normalize(ie.value, y_factor);
                            fprintf(stderr, "%ld.%06ld: REL_Y %d\n", rel_t.tv_sec, rel_t.tv_usec, val);
                            break;

                        case REL_WHEEL:
                            val = ie.value;
                            fprintf(stderr, "%ld.%ld: REL_WHEEL %d\n", rel_t.tv_sec, rel_t.tv_usec, val);
                            break;

                        /* Continue, if the event code is not of interest */
                        default:
                            continue;
                    }
                    if (store_event(&rel_t, &(ie.type), &(ie.code), &val, fout) < 4)
                        fprintf(stderr, "Error storing event!\n");;
                }

                /* Handles button presses, no need to normalize */
                if (ie.type == EV_KEY)
                {
                    switch (ie.code)
                    {
                        case BTN_LEFT:
                            val = ie.value;
                            fprintf(stderr, "%ld.%ld: BTN_LEFT %d\n", rel_t.tv_sec, rel_t.tv_usec, (int)val);
                            break;
                        case BTN_MIDDLE:
                            val = ie.value;
                            fprintf(stderr, "%ld.%ld: BTN_MIDDLE %d\n", rel_t.tv_sec, rel_t.tv_usec, (int)val);
                            break;
                        case BTN_RIGHT:
                            val = ie.value;
                            fprintf(stderr, "%ld.%ld: BTN_RIGHT %d\n", rel_t.tv_sec, rel_t.tv_usec, (int)val);
                            break;
                        default:
                            /* Key presses, no need to normalize */
                            fprintf(stderr, "%ld.%ld: Key press %d %d\n", rel_t.tv_sec, rel_t.tv_usec, ie.code, ie.value);
                            val = ie.value;
                            break;
                    }
                    if (store_event(&rel_t, &(ie.type), &(ie.code), &val, fout) < 4)
                        fprintf(stderr, "Error storing event!\n");;
                }
                val = 0;
            }
        }

        /* Checks, if capture time is up */
        gettimeofday(&t2, NULL);
        if (end_t.tv_sec > 0 && t2.tv_sec == end_t.tv_sec ? t2.tv_usec > end_t.tv_usec : t2.tv_sec > end_t.tv_sec)
            is_stopping = 1;
    }
    return 0;
}

int populate_fds(struct pollfd* fds, char** event_files, size_t n)
{
    int fd_event;

    for (size_t i = 0; i < n; i++)
    {
        /* Opens event file */
        fd_event = open(event_files[i], O_RDONLY);

        if (fd_event == -1)
        {
            fprintf(stderr, "Error opening device %s\n", event_files[i]);
            return 1;
        }
        fds[i].fd = fd_event;
        fds[i].events = POLLIN;
    }
    return 0;
}
int record(char** event_files, size_t n, const char* output_file, int seconds)
{
    /* FDs of event files to poll */
    struct pollfd fds[n];

    /* Prepares event files to poll from */
    if (populate_fds(fds, event_files, n) == 1)
        return 1;

    /* Retrieves display dimensions, needed for coordate normalization */
    unsigned int w, h = -1;
    if (get_dimensions(&w, &h) == 1)
    {
        fprintf(stderr, "Failed to retrieve display dimensions");
        return 1;
    }

    fprintf(stderr, "Screen dimensions: %d x %d\n", w, h);

    /* Centers cursor for reproducible replay */
    if (center_cursor(w, h) != 0)
    {
        fprintf(stderr, "Could not center cursor");
        return 1;
    }

    /* Buffered stream to write to */
    FILE* fout = NULL;

    /* Opens output file or STDOUT, if not specified */
    if (output_file && strlen(output_file) > 0)
    {
        fprintf(stderr, "Opening %s\n", output_file);

        /* Use creat-syscall to open file with restrictive permissions right away */
        int fd = creat(output_file, 0664);

        if (fd == -1)
        {
            perror("creat()");
            return 1;
        }

        fout = fdopen(fd, "w");
    }
    else
    {
        /* Write to stdout */
        fout = stdout;
    }

    if (fout == NULL)
    {
        fprintf(stderr, "Could not open file %s\n",
            output_file && strlen(output_file) > 0 ? output_file : "stdout");
        return 1;
    }

    write_file_header(fout);

    /* Map recorded coordinates into  value range used by QMP */
    double x_scale = (float)(1<<15)/w;
    double y_scale = (float)(1<<15)/h;
    fprintf(stderr, "Scaling factors: X * %f -  Y * %f\n", x_scale, y_scale);

    poll_events(fds, n, fout, seconds, x_scale, y_scale);

    if (fclose(fout) != 0)
        return 1;

    fprintf(stderr, "File successfully closed.\n");

    return 0;
}

void print_help(const char* prog_name)
{
    fprintf(stderr, "usage: %s [-h] [-e /dev/input/eventX] [file]\n", prog_name);
    fprintf(stderr, "\nA utility to record HID events\n");
    fprintf(stderr, "\npositional arguments:\n");
    fprintf(stderr, "  file\t\tbinary file to store events\n");
    fprintf(stderr, "\noptional arguments:\n");
    fprintf(stderr, "  -h\t\t\tshow this help message and exit\n");
    fprintf(stderr, "  -e <eventfile>\tevent file to read events from;\n\t\t  multiple event files can be specifed -e file1 -e file2 (max. 3)\n");
    fprintf(stderr, "  -d <seconds>\t\ttime frame in seconds to record events\n");
    fprintf(stderr, "\nexamples:\n");
    fprintf(stderr, "  # capture mouse events infinitely\n");
    fprintf(stderr, "  %s > events.in \n", prog_name);
    fprintf(stderr, "\n  # read from specified event files for 20 secs\n");
    fprintf(stderr, "  %s -e /dev/input/event7 -e /dev/input/event16 -d 20 events.bin\n", prog_name);
    fprintf(stderr, "\nIf no output file is specified as a positional argument, all events will be sent to stdout.\n");
    fprintf(stderr, "If no event file is specified via '-e', the default event file for mouse events will be used.\n");
    fprintf(stderr, "To capture events of a specific input device, use '-e' after retrieving the relevant event file via\n");
    fprintf(stderr, "\n\tls -l /dev/input/by-id | grep -E \"mouse|kbd\"\n");
    fprintf(stderr, "\nor alternatively\n");
    fprintf(stderr, "\n\tcat /proc/bus/input/devices | grep -E \"mouse|kdb\"\n");
    fprintf(stderr, "\n%s Copyright\t\t(C) 2021 Jan Gruber\n", prog_name);
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
    /* Variables for file interaction */
    char* event_files[MAX_EVENT_FILES] = {NULL};
    size_t eidx = 0;
    char* output_file = NULL;
    int duration = -1;

    /* Variables for argument handling */
    int opt;
    extern char* optarg;
    extern int optind, opterr, optopt;

    /* Installs signal handler to ensure clean shut down */
    if (install_signal_handler(SIGINT) || install_signal_handler(SIGTERM) ||
        install_signal_handler(SIGHUP))
    {
        fprintf(stderr, "Error setting up signal handlers\n");
        return EXIT_FAILURE;
    }

    /* Reads CLI arguments */
    while ((opt = getopt(argc, argv, "e:d:h")) != -1)
    {
        switch (opt)
        {
            case 'e':
                fprintf(stderr, "Using event file %s\n", optarg);
                char* evt = strdup(optarg);
                event_files[eidx] = evt;
                eidx++;
                break;
            case 'd':
                duration = atoi(optarg);
                fprintf(stderr, "Setting duration %d secs\n", duration);
                break;
            case ':':
                fprintf(stderr, "Error: Option needs a value\n");
                print_help(argv[0]);
                break;
            case 'h':
            /* Fall through */
            default:
                print_help(argv[0]);
                return EXIT_SUCCESS;
        }
    }

    /* Finds active event file, if not a single one was supplied via -e */
    if (eidx == 0)
    {
        char* event_file = NULL;
        if (find_event_file(&event_file) != 0)
        {
            fprintf(stderr, "Failed to retrieve event file; Specify it explicitely!\n");
            return EXIT_FAILURE;
        }
        event_files[eidx++] = event_file;
        fprintf(stderr, "Retrieved mouse event file %s\n", event_file);
    }

    /* Handles positional argument */
    if (optind < argc)
    {
        output_file = strdup(argv[optind]);
        fprintf(stderr, "Writing output to %s\n", output_file);
    }

    /* Start recording mouse movements */
    record(event_files, eidx, output_file, duration);

    /* Clean up heap allocated variables */
    if (output_file)
        free(output_file);

    for (size_t i = 0; i < MAX_EVENT_FILES; i++)
        if (event_files[i])
            free(event_files[i]);

    return EXIT_SUCCESS;
}
