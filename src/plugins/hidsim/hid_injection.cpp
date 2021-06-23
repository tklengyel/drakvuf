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
 * This file was created by Jan Gruber.                                    *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/

#include<fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/time.h>
#include <math.h>

#include <libdrakvuf/libdrakvuf.h> /* eprint_current_time */
#include "../private.h" /* PRINT_DEBUG */

/* Hidsim specific includes */
#include "keymap_evdev_to_qapi.h" /* Mapping evdev->qapi name */
#include "qmp_connection.h"
#include "hid_injection.h"

/* Drakvuf HID template */
#define DRAK_MAGIC_NUMBER 0xc4d2c1cb
#define DRAK_MAGIC_STR 0x4b415244
#define HEADER_LEN 0xC

#define PPM_MAGIC_NUMBER "P6"

/* Length of the QMP command buffer */
#define CMD_BUF_LEN 0x400

/* QAPI's button values */
#define L_BTN_STR "left"
#define M_BTN_STR "middle"
#define R_BTN_STR "right"

/* Throttle injection down to 50 microsec intervals */
#define TIME_BIN 50

struct dimensions
{
    int width;      /* display width */
    int height;     /* display height */
    float dx;       /* one pixel equivalent on x-axis */
    float dy;       /* one pixel equivalent on y-axis */
};

/* Keep track of the current cursor position */
int new_x = 1 << 14;
int new_y = 1 << 14;

static int dump_screen(qmp_connection* qc, const char* path)
{
    char cmd[0x200];
    snprintf(cmd, 0x200,
        QMP_SCREEN_DUMP_FMT_STR,
        path);
    char* out = NULL;

    qmp_communicate(qc, cmd, &out);

    if (strcmp(out, QMP_SUCCESS) != 0)
    {
        fprintf(stderr, "[HIDSIM]: Error dumping screen - %s\n", out);
    }
    return 0;
}

/* For absolute pointing devices 2^15 is used to specify maximum */
static float calculate_pixel_unit(int u)
{
    return (float)(1<<15)/u;
}

/* Retrieves display dimensions for coordination of mouse movements */
static int get_display_dimensions(qmp_connection* qc, struct dimensions* dims)
{
    const char* tmp_path = "/tmp/tmp.ppm";

    /* Dumps screen via QMP-command and stores result at tmp_path */
    if (dump_screen(qc, tmp_path) != 0)
        return -1;

    /* Extracts display size from .ppm-file created by screendump */
    FILE* fr = fopen(tmp_path, "r");
    char ppm_hdr[3];
    int matches = 0;
    int ret = 0;

    /* Checks PPM-header */
    matches = fscanf(fr, "%s", ppm_hdr);

    if (matches != 1 || strcmp(ppm_hdr, PPM_MAGIC_NUMBER) != 0)
        ret = -1;

    /* Reads actual dimensions */
    matches = fscanf(fr, "%d%d", &(dims->width), &(dims->height));

    /* Calculates pixel mapping */
    dims->dx = calculate_pixel_unit(dims->width);
    dims->dy = calculate_pixel_unit(dims->height);

    if (matches != 2 || dims->width < 0 || dims->height < 0)
        ret = -1;

    /* Clean up */
    if (remove(tmp_path) != 0)
        fprintf(stderr, "[HIDSIM]: Error deleting screen dump %s\n", tmp_path);

    PRINT_DEBUG("[HIDSIM] Screen dimension: %d x %d\n", dims->width, dims->height);
    return ret;
}

/* Parses header of HID-template-file */
static int read_header(FILE* f)
{
    uint32_t magic, drak, version;
    int nr = 0;

    nr += fread(&magic, sizeof(magic), 1, f);       /* 0xc4d2c1cb */
    nr += fread(&drak, sizeof(drak), 1, f);         /* 0x4b415244 */
    nr += fread(&version, sizeof(version), 1, f);
    if (nr < 3)
    {
        fprintf(stderr, "[HIDSIM] Generic error reading file header of HID-template\n");
        return 1;
    }

    if (magic != DRAK_MAGIC_NUMBER || drak != DRAK_MAGIC_STR)
    {
        fprintf(stderr, "[HIDSIM] Error parsing header of HID-template\n");
        return 1;
    }

    return 0;
}

/* Constructs a QMP event-string to instruct a mouse movement */
static void construct_move_mouse_event(char* buf, int len, int x, int y, bool is_rel)
{
    const char* type = is_rel ? "rel" : "abs";
    snprintf(buf + strlen(buf), len - strlen(buf), QMP_MOUSE_MOVE_EVENT_FMT_STR,
        type, x, type, y);
}

/* Constructs a QMP event-string for sending a button press or release */
static void construct_button_event(char* buf, int len, const char* btn, int is_down, bool is_append)
{
    const char* type = is_down ? "true" : "false";
    snprintf(buf + strlen(buf), len + strlen(buf),
        QMP_MOUSE_BTN_EVENT_FMT_STR,
        type, btn, is_append ? ',' : ' ');
}

/* Constructs a QMP event-string to send key down or up-command */
static void construct_key_event(char* buf, int len, const unsigned int key, bool is_down, bool is_append)
{
    /*
     * For some reason sending QKeyCodes as their numbers does not work reliably.
     * Therefore it is required to map EvDev codes to the QAPI-names of QKeyCodes,
     * which QMP understands
     *
     */
    const char* state = is_down ? "true" : "false";
    const char* qapi_name = NULL;


    if (key < name_map_linux_to_qcode_len)
    {
        /*
         * Since raw values do not reliably work in (at least) Windows guests,
         *convert to qapi-names of QKeyCodes!
         */
        qapi_name = name_map_linux_to_qcode[key];
        snprintf(buf + strlen(buf), len - strlen(buf),
            QMP_KEY_PRESS_QAPI_FMT_STR,
            state, qapi_name, is_append ? ',' : ' ');
    }
    else
        /* Send raw evdev representation as fallback */
        snprintf(buf + strlen(buf), len - strlen(buf),
            QMP_KEY_PRESS_CODE_FMT_STR,
            state, key, is_append ? ',' : ' ');
}

/* Helper function to center cursor */
static void center_cursor(qmp_connection* qc)
{
    /* Command buffer */
    char buf[CMD_BUF_LEN];

    /* 2^15 == max, 2^14 == max/2 */
    construct_move_mouse_event(buf, CMD_BUF_LEN, 1<<14, 1<<14, false);
    qmp_communicate(qc, buf, NULL);
}

/* Resets file stream, timer and cursor position */
static int reset_hid_injection(qmp_connection* qc, FILE* f, struct timeval* tv, int* nx, int* ny)
{
    /* Jumps to the beginning of the HID data */
    int ret = fseek(f, HEADER_LEN, SEEK_SET);

    /* Center coords */
    *nx = 1 << 14;
    *ny = 1 << 14;
    center_cursor(qc);

    timerclear(tv);

    return ret;
}
/* Processes evdev-events, which encode keypresses/-releases */
static void handle_key_event(input_event* ie, char* buf, size_t n, bool is_append)
{
    /* Ignores value 2 -> key still pressed */
    if (ie->value == 0  || ie->value == 1)
        construct_key_event(buf, n, ie->code, (const unsigned int) ie->value, is_append);
}

/* Processes evdev-events, which encode mouse button presses/releases */
static void handle_btn_event(input_event* ie, char* buf, size_t n, bool is_append)
{
    if (ie->code == BTN_LEFT)
    {
        construct_button_event(buf, n, L_BTN_STR, ie->value, is_append);
    }
    if (ie->code == BTN_MIDDLE)
    {
        construct_button_event(buf, n, M_BTN_STR, ie->value, is_append);
    }
    if (ie->code == BTN_RIGHT)
    {
        construct_button_event(buf, n, R_BTN_STR, ie->value, is_append);
    }
}

/* Processes Evdev-events, which encode mouse movements */
static void handle_move_event(input_event* ie, char* buf, size_t n, int* nx, int* ny, bool is_append)
{
    if (ie->code == REL_X)
    {
        *nx += ie->value;
    }
    if (ie->code == REL_Y)
    {
        *ny += ie->value;
    }
    /*
     * For mouse movements only coords have to be updated,
     * when appending is requested
     */
    if (!is_append)
        construct_move_mouse_event(buf, n, *nx, *ny, false);
}

/* Takes an input event and delegates the construction of a QMP event-string accordingly */
static void handle_event(input_event* ie, char* buf, size_t n, bool is_append)
{
    /* Handles mouse move events */
    if (ie->type == EV_REL)
    {
        /* Converts to absolute coordinates */
        handle_move_event(ie, buf, n, &new_x, &new_y, is_append);

    }
    if (ie->type == EV_KEY)
    {
        if (ie->code < 0x100)
            handle_key_event(ie, buf, n, is_append);

        if (ie->code > 255 && ie->code < 0x120)
            handle_btn_event(ie, buf, n, is_append);
    }
}

/* Calculates the length of a hypotenuse */
double hypot(double a, double b)
{
    return sqrtf(a*a + b*b);
}

/* Returns a random number n, while a <= n < b */
int rand_approx_uniform(int a, int b)
{
    return a + rand() % (b - a + 1);
}

/*
 * Marsaglia polar method to generate gaussian distributed random variables
 * Slightly modified version from
 * https://en.wikipedia.org/wiki/Marsaglia_polar_method
 */
double gaussian_rand (double mean, double sigma)
{
    double u, v, w, s;
    /*
     * Two random variables are generated in one iteration
     * they have a mean 0 and a std dev of 1
     * Static to hold value for next call
     */
    static double spare;
    static bool has_spare = 0;

    if (has_spare)
    {
        /* No computation needed, if it is the second call and x2 is buffered */
        has_spare = false;

        /* Transform x2 within [-1, 1] to the specified output range */
        return (mean + sigma * spare);
    }

    do
    {
        /* Scale it to [-1, 1] by calculating -low + x * (high - low) */
        u = -1 + ((double)rand() / RAND_MAX) * 2;
        v = -1 + ((double)rand() / RAND_MAX) * 2;
        w = u * u + v * v;
    }
    /* Avoids division by 0 */
    while (w >= 1 || (w < 0.0000000000000001 && w > -0.0000000000000001));

    s = sqrt(-2.0 * log(w) / w);
    spare = v * s;
    has_spare = true;

    return (mean + sigma * u * s);
}

/* Smoothly moves the cursor to new coordinates in a given time frame */
void translate(qmp_connection* qc, dimensions* dim, int time_frame, int ox, int oy, int dx, int dy, int* newx, int* newy)
{

    /* Command buffer */
    char buf[CMD_BUF_LEN];

    const float DISP_RES = dim->dx < dim->dy ? dim->dy : dim->dx;
    int nx, ny;
    int sleep, s;
    nx = ox + dx;
    ny = oy + dy;

    /* Bounds checking in X-axis*/
    if (nx <= 0)
    {
        nx = 0;
        dx = nx - ox;
    }
    else if (nx > (1 << 15) - 2)
    {
        nx = (1 << 15) - 2;
        dx = nx - ox;
    }
    /* Bounds checking Y-axis */
    if (ny <= 0)
    {
        ny = 0;
        dy = ny - oy;
    }
    else if (ny > (1 << 15) - 2)
    {
        ny = (1 << 15) - 2;
        dy = ny - oy;
    }

    /* Lenght of the vector specified - ||(nx-cx, ny-cy)||  */
    double d;

    /* Current displacement in the respective axis */
    double cdx, cdy;

    /* Current cursor position in absolute coords */
    int cx = ox;
    int cy = oy;

    /* Sleep time between micro movements */
    sleep = time_frame / (hypot(dx, dy) / DISP_RES);

    /*
     * Inspired by
     * https://github.com/autopilot-rs/autopy-legacy/blob/1cbf4e842c4d43f706a16ac6106f77031ab00163/src/mouse.c#L151
     */
    while ((d = hypot((double)(nx - cx), (double)(ny - cy))) > DISP_RES)
    {
        /* Calculate normalized displacement vector */
        cdx = ((double)(nx - cx) / d);
        cdy = ((double)(ny - cy) / d);

        /* Calculates the current position of the cursor in absolute coords */
        cx += floor(cdx * dim->dx + 0.5);
        cy += floor(cdy * dim->dy + 0.5);

        /* Checks screen boundaries */
        if (cx < 0 || cx > 1 << 15 || cy < 0 || cy > 1 << 15)
        {
            break;
        }

        snprintf(buf, CMD_BUF_LEN, "%s", QMP_SEND_INPUT_OPENING);
        construct_move_mouse_event(buf, CMD_BUF_LEN, cx, cy, false);
        snprintf(buf + strlen(buf), CMD_BUF_LEN - strlen(buf), "%s", QMP_SEND_INPUT_CLOSING);
        qmp_communicate(qc, buf, NULL);
        buf[0] = '\0';

        /* Randomize the sleep */
        s = (int) gaussian_rand((float)sleep, sleep/16);
        usleep(s);
    }
    *newx = cx;
    *newy = cy;

}

/* Injects random mouse movements */
static int run_random_injection(qmp_connection* qc, sig_atomic_t* has_to_stop)
{
    PRINT_DEBUG("[HIDSIM] injecting random mouse movements\n");
    struct dimensions dim;

    /* Needed for retrieval of screen resolution */
    if (get_display_dimensions(qc, &dim) != 0)
        return -1;

    center_cursor(qc);

    int nx, ny;
    int oy = 1<<14;
    int ox = 1<<14;
    int dx = 0;
    int dy = 0;

    /* Defines maximum displacement */
    int MAX_DIST_X = (1<<15)/4;
    int MIN_DIST_X = -1 * MAX_DIST_X;
    int MAX_DIST_Y = (1<<15)/4;
    int MIN_DIST_Y = -1 * MAX_DIST_Y;

    int sleep = 0;
    int time_frame = 0;

    /* Seed RNG */
    timeval t;
    gettimeofday(&t, NULL);
    srand(t.tv_sec);
    int s = rand()%512;
    /* Loops, until stopped */
    while (!*has_to_stop)
    {
        /* Calculates the random displacement of the mouse cursor */
        dx = rand_approx_uniform(MIN_DIST_X, MAX_DIST_X);
        dy = rand_approx_uniform(MIN_DIST_Y, MAX_DIST_Y);

        /* Calculates the actual distance to cover */
        int dist = (int) hypot(dx, dy);

        /*
         * Takes the distance to cover to derive the time frame
         * Here a random number from a gaussian distribution is drawn,
         * so that the velocity of the cursor movements varies
         */
        time_frame = gaussian_rand(dist * 12, dist * 24);

        /* Reverse negative */
        time_frame = time_frame < dist ? dist + (dist-time_frame) : time_frame;

        /* Moves the cursor smoothy */
        translate(qc, &dim, (int)time_frame, ox, oy, dx, dy, &nx, &ny);

        ox = nx;
        oy = ny;

        /* Gaussian distributed waiting between smooth movements */
        sleep = (int) gaussian_rand(0, 10000);
        if (sleep>0)
            usleep(sleep);
        s++;
    }

    return 0;
}

/* Performs HID event injection according to pre-recorded Evdev-events given by a binary file */
static int run_template_injection(qmp_connection* qc, FILE* f, sig_atomic_t* has_to_stop)
{
    PRINT_DEBUG("[HIDSIM] running template injection\n");

    /* Command buffer */
    char cmd[CMD_BUF_LEN];

    /* Event buffer */
    char buf[CMD_BUF_LEN];

    /* Evdev events to inject */
    struct input_event ie_next, ie_cur;

    /* Keeping track of time */
    struct timeval tv_old;
    struct timeval tv_diff;

    size_t nr = 0;
    long int sleep = 0;
    bool was_last = true;

    /* Reads first event */
    nr = fread(&ie_cur, sizeof(ie_cur), 1, f);

    /* Waits until first event should be injected */
    sleep = ie_cur.time.tv_sec * 1000000 * ie_cur.time.tv_usec;
    usleep(sleep);

    while (!*has_to_stop)
    {
        /* Handles the special case of the first event */
        if (was_last)
        {
            /* Prepares injection by initializing all variables */
            if (reset_hid_injection(qc, f, &tv_old, &new_x, &new_y) != 0)
            {
                fprintf(stderr, "[HIDSIM] Error resetting HID injection");
                return 1;
            }
            was_last = false;
        }

        /* Reads the follow-up event */
        nr = fread(&ie_next, sizeof(ie_next), 1, f);

        if (nr == 0) /* EOF was reached */
        {
            /* Iteration deals with last event in template */
            was_last = true;
            /* Resets time for the repeat */
            timerclear(&ie_cur.time);
            /* Ensures injection of pending events */
            sleep = TIME_BIN +1;
        }
        else
        {
            timersub(&ie_next.time, &ie_cur.time, &tv_diff);
            sleep = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
        }
        /*
         * Throttles event injection, by combing all events within a timeframe of 50 usecs
         * This performs actually a binning with bin size of 50 usecs
         */
        if ( sleep > TIME_BIN)
        {
            /* Constructs event-string corresponding to evdev-event in question */
            handle_event(&ie_cur, buf, CMD_BUF_LEN, false);

            /* Constructs execute-buffer containing various events */
            snprintf(cmd, CMD_BUF_LEN, "%s", QMP_SEND_INPUT_OPENING);
            snprintf(cmd + strlen(cmd), CMD_BUF_LEN - strlen(cmd), "%s", buf);
            snprintf(cmd + strlen(cmd), CMD_BUF_LEN - strlen(cmd), "%s", QMP_SEND_INPUT_CLOSING);

            /* Sends command buffer */
            qmp_communicate(qc, cmd, NULL);
            PRINT_DEBUG("[HIDSIM] %s\n", cmd);

            /* Resets event buffer */
            buf[0] = '\0';
        }
        else
        {
            /* Converts evdev-event to qmp-string and appends it to buffer */
            handle_event(&ie_cur, buf, CMD_BUF_LEN, true);
        }
        /* Omits sleeping after injection of last event */
        if (!was_last)
        {
            usleep(sleep);
            ie_cur = ie_next;
        }
    }
    return 0;
}

/* Cleans up and frees ressources */
static int hid_cleanup(qmp_connection* qc, int fd, FILE* f)
{
    int ret = 0;

    if (qc)
        if ((ret = qmp_close_conn(qc)) != 0)
            fprintf(stderr, "[HIDSIM] Error closing QMP socket %s\n", qc->sa.sun_path);
    if (f)
        if ((ret = fclose(f)) != 0)
            fprintf(stderr, "[HIDSIM] Error closing %p", f);
    if (fd >= 0)
        if ((ret = close(fd)) != 0)
            fprintf(stderr, "[HIDSIM] Error closing %d\n", fd);

    return ret;
}

/* Worker thread function */
int hid_inject(const char* sock_path, const char* template_path, sig_atomic_t* has_to_stop)
{
    /* Initializes qmp connection */
    qmp_connection qc;
    int sc = 0;
    int fd = -1;
    FILE* f = NULL;

    if (qmp_init_conn(&qc, sock_path) < 0)
    {
        fprintf(stderr, "[HIDSIM] Could not connect to Unix Domain Socket %s.\n", sock_path);
        return 1;
    }

    if (template_path != NULL && strlen(template_path)>0)
    {
        fd = open(template_path, O_RDONLY);

        if (fd < 0)
        {
            fprintf(stderr, "[HIDSIM] Error opening file %s\n", template_path);
            hid_cleanup(&qc, fd, NULL);
            return 1;
        }

        /* Asks for aggressive readahead */
        if (posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL)!=0)
        {
            fprintf(stderr, "[HIDSIM] Asking for aggressive readahead on FD %d failed. Continuing anyway...\n", fd);
        }

        f = fdopen(fd, "rb");

        if (!f)
        {
            fprintf(stderr, "[HIDSIM] Error reading from %s\n", template_path);
            hid_cleanup(&qc, fd, NULL);
            return 1;
        }

        if (read_header(f) != 0)
        {
            fprintf(stderr, "[HIDSIM] Not a valid HID template file. Stopping\n");
            hid_cleanup(&qc, fd, f);
            return 1;
        }

        /* Performs actual injection */
        sc = run_template_injection(&qc, f, has_to_stop);
    }
    else
    {
        sc = run_random_injection(&qc, has_to_stop);
    }
    if (sc != 0)
        fprintf(stderr, "[HIDSIM] Error performing HID injection\n");

    hid_cleanup(&qc, fd, f);

    return 0;
}
