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

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/time.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <math.h>
#include <random>

#include <libdrakvuf/libdrakvuf.h> /* eprint_current_time */
#include "../private.h" /* PRINT_DEBUG */

/* Hidsim specific includes */
#include "qmp/keymap_evdev_to_qapi.h"
#include "qmp/qmp_connection.h"
#include "qmp/qmp_commands.h"
#include "hid_injection.h"

/* Drakvuf HID template */
#define DRAK_MAGIC_NUMBER 0xc4d2c1cb
#define DRAK_MAGIC_STR 0x4b415244
#define HEADER_LEN 0xC

/* Constants for determining screensize */
#define PPM_MAGIC_NUMBER "P6"
#define SCREEN_MAX_8K 7680

/* Length of the QMP command buffer */
#define CMD_BUF_LEN 0x400

/* Throttle injection down to 50 microsecond intervals */
#define TIME_BIN 50
#define MAX_SLEEP 10 * 1000000
#define CLK_MEAN 6
#define CLK_SIGMA 6
/*
 * Replaces the flawed rand()-function of C's standard library with the
 * Mersenne Twister implementation
 */
static std::mt19937 _rand;

typedef struct dimensions
{
    /* Max screensize 65536 x 65536 */
    uint16_t width;      /* Display width */
    uint16_t height;     /* Display height */

    /* Mapping factors for QMP */
    float dx;       /* One pixel equivalent on x-axis */
    float dy;       /* One pixel equivalent on y-axis */
} dimensions;

/* Keep track of the current cursor position */
int new_x = 1 << 14;
int new_y = 1 << 14;

/*
 * Dumps the screen by using QMP's screendump-command and stores the result
 * as the specified file
 */
static int dump_screen(qmp_connection* qc, const char* path)
{
    struct json_object* cmd = construct_screendump_cmd(path);

    json_object* out = NULL;

    qmp_communicate_json(qc, cmd, &out);

    if (qmp_check_result_json(out))
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error dumping screen");
        json_object_put(out);
        json_object_put(cmd);
        return -1;
    }

    json_object_put(out);
    json_object_put(cmd);

    return 0;
}

/*
 * For absolute pointing devices 2^15 is used to specify the maximum of each
 * axis regardless of the actual screen resolution
 */
static float calculate_pixel_unit(int u)
{
    return (float)(1<<15)/u;
}

/* Retrieves display dimensions for coordination of mouse movements */
static int get_display_dimensions(qmp_connection* qc, dimensions* dims)
{
    const char* tmp_path = "/tmp/tmp.ppm";

    /* Dumps screen via QMP as .ppm-file and stores result at tmp_path */
    if (dump_screen(qc, tmp_path) != 0)
        return -1;

    /* Extracts display size from .ppm-file created by screendump */
    FILE* f = fopen(tmp_path, "r");
    if (!f)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error extracting display size from"
            " %s\n", tmp_path);
        return -1;
    }

    char ppm_hdr[3];
    int matches = 0;

    /* Reads first three bytes of the potential portable pixmap */
    matches = fscanf(f, "%2s", ppm_hdr);

    /* Checks PPM-header */
    if (matches != 1 || strcmp(ppm_hdr, PPM_MAGIC_NUMBER) != 0)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error reading .ppm-files's magic number\n");
        fclose(f);
        return -1;
    }

    /* Retrieves screen dimensions by reading screen dump  */
    uint32_t width = 0, height = 0;
    matches = fscanf(f, "%" SCNd32 "%" SCNd32, &width, &height);

    /* Clean up */
    fclose(f);

    if (matches != 2)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error reading .ppm-files metadata\n");
        return -1;
    }

    /*
     * Sanitize read values by guarding against a potential division by zero
     * and checking for utopian big screen sizes.
     */
    if (width == 0 || height == 0 ||
        width > SCREEN_MAX_8K || height > SCREEN_MAX_8K)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Unsupported screensize\n");
        return -1;
    }

    dims->width = (uint16_t) width;
    dims->height = (uint16_t) height;

    /* Removes temp file generated by the screendump-command */
    if (remove(tmp_path) != 0)
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error deleting screen dump %s\n", tmp_path);

    /* Calculates pixel mapping */
    dims->dx = calculate_pixel_unit(dims->width);
    dims->dy = calculate_pixel_unit(dims->height);

    PRINT_DEBUG("[HIDSIM] [INJECTOR] Screen dimension: %d x %d\n",
        dims->width, dims->height);

    return 0;
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
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error reading header of HID-template\n");
        return 1;
    }

    if (magic != DRAK_MAGIC_NUMBER || drak != DRAK_MAGIC_STR)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error parsing header of HID-template\n");
        return 1;
    }

    return 0;
}

/* Helper function to send a mouse move command via qmp */
static void move_mouse(qmp_connection* qc, int x, int y, bool is_abs)
{
    struct json_object* cmd, *events;

    /* Array to hold an event for each axis */
    events = json_object_new_array();

    /* Constructs events for x- and y-axis */
    json_object_array_add(events,
        construct_mouse_move_event(ax_x, is_abs, x));
    json_object_array_add(events,
        construct_mouse_move_event(ax_y, is_abs, y));

    /* Wraps it */
    cmd = construct_input_event_cmd(events);

    /* Sends command */
    qmp_communicate_json(qc, cmd, NULL);

    /* Clean up */
    json_object_put(cmd);
}


/* Helper function to center cursor */
static void center_cursor(qmp_connection* qc)
{
    move_mouse(qc, 1<<14, 1<<14, true);
}

/* Resets file stream, timer and cursor position */
static int reset_hid_injection(qmp_connection* qc, FILE* f, struct timeval* tv,
    int* nx, int* ny)
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
static struct json_object* handle_key_event(struct input_event* ie)
{
    /* Ignores value 2 -> key still pressed */
    if (ie->value == 0  || ie->value == 1)
        return construct_qapi_keypress_event(ie->code, ie->value);
    return NULL;
}

/* Processes evdev-events, which encode mouse button presses/releases */
static struct json_object* handle_btn_event(struct input_event* ie)
{
    if (ie->code == BTN_LEFT)
    {
        return construct_mouse_button_event(left, ie->value);
    }
    if (ie->code == BTN_MIDDLE)
    {
        return construct_mouse_button_event(middle, ie->value);
    }
    if (ie->code == BTN_RIGHT)
    {
        return construct_mouse_button_event(middle, ie->value);
    }

    return NULL;
}

/* Processes Evdev-events, which encode mouse movements */
static struct json_object* handle_move_event(struct input_event* ie, int* nx, int* ny)
{
    int* v = NULL;
    enum AXIS_ENUM ax;

    if (ie->code == REL_X)
    {
        *nx += ie->value;
        v = nx;
        ax = ax_x;
    }
    if (ie->code == REL_Y)
    {
        *ny += ie->value;
        v = ny;
        ax = ax_y;
    }

    if (v)
        return construct_mouse_move_event(ax, true, *v);

    /* Return NULL for an irrelevant axis */
    return NULL;
}

/*
 * Takes an input event and delegates the construction of a QMP
 * event-string accordingly
 */
struct json_object* handle_event(struct input_event* ie)
{
    /* Handles mouse move events */
    if (ie->type == EV_REL)
    {
        /*
         * Converts to absolute coordinates and returns qmp-event-str,
         * if it should not be "appended"
         */
        return handle_move_event(ie, &new_x, &new_y);

    }
    if (ie->type == EV_KEY)
    {
        if (ie->code < 0x100)
            return handle_key_event(ie);

        if (ie->code > 255 && ie->code < 0x120)
            return handle_btn_event(ie);
    }
    return NULL;
}

/* Calculates the length of a hypotenuse */
double hypot(double a, double b)
{
    return sqrtf(a*a + b*b);
}

/* Returns a random number n, while a <= n < b */
int rand_approx_uniform(int a, int b)
{
    return a +_rand() % (b - a + 1);
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
        u = -1 + ((double)_rand() / RAND_MAX) * 2;
        v = -1 + ((double)_rand() / RAND_MAX) * 2;
        w = u * u + v * v;
    }
    /* Avoids division by 0 */
    while (w >= 1 || (w < 0.0000000000000001 && w > -0.0000000000000001));

    s = sqrt(-2.0 * log(w) / w);
    spare = v * s;
    has_spare = true;

    return (mean + sigma * u * s);
}

/* Clicks on current cursor location */
void click(qmp_connection* qc, BTN_ENUM b)
{
    struct json_object* cmd, *evt, *events;

    events = json_object_new_array();

    /* Button down */
    evt = construct_mouse_button_event(b, true);
    json_object_array_add(events, evt);
    cmd = construct_input_event_cmd(events);

    /* Sends command */
    qmp_communicate_json(qc, cmd, NULL);
    PRINT_DEBUG("[HIDSIM] [INJECTOR] %s\n", json_object_to_json_string_ext(cmd,
            JSON_C_TO_STRING_SPACED));

    /* Keep the button down a litte */
    usleep(500);

    /* Resets event buffer */
    json_object_put(cmd);

    events = json_object_new_array();

    /* Button up  */
    evt = construct_mouse_button_event(b, false);
    json_object_array_add(events, evt);

    cmd = construct_input_event_cmd(events);
    qmp_communicate_json(qc, cmd, NULL);
    PRINT_DEBUG("[HIDSIM] [INJECTOR] %s\n", json_object_to_json_string_ext(cmd,
            JSON_C_TO_STRING_SPACED));

    /* Resets event buffer */
    json_object_put(cmd);

}

/* Smoothly moves the cursor to new coordinates in a given time frame */
void translate(qmp_connection* qc, dimensions* dim, int time_frame,
    int ox, int oy, int dx, int dy, int* newx, int* newy)
{
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
     * https://github.com/autopilot-rs/autopy-legacy/blob/\
     * 1cbf4e842c4d43f706a16ac6106f77031ab00163/src/mouse.c#L151
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

        move_mouse(qc, cx, cy, true);

        /* Randomize the sleep */
        s = (int) gaussian_rand((float)sleep, sleep/16);
        usleep(s);
    }
    *newx = cx;
    *newy = cy;
}

/* Injects random mouse movements */
static int run_random_injection(qmp_connection* qc, bool is_rand_clicks,
    std::atomic<uint32_t>* coords, std::atomic<bool>* has_to_stop)
{
    PRINT_DEBUG("[HIDSIM] [INJECTOR] Injecting random mouse movements\n");
    dimensions dim;

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
    /* Spare areas (probably taskbar and icons) */
    int LEFT_THRES = (1<<16) * 0.2;
    int BOTTOM_THRES = (1<<16) - ((1<<16) * 0.2);

    int sleep = 0;
    int time_frame = 0;

    int s = _rand()%512;

    bool is_click = false;
    int moves_next_click = gaussian_rand(CLK_MEAN, CLK_SIGMA);

    /* Loops, until stopped */
    while (!has_to_stop->load())
    {

        if (coords->load())
        {
            uint32_t cur_coords = coords->load();
            /* Retrieves coords to click next */
            dx = (uint16_t) (( cur_coords >> 16) * dim.dx) - ox ;
            dy = (uint16_t) (( cur_coords & 0xFFFF) * dim.dy) - oy;
            coords->store(0);

            is_click = true;
        }
        else
        {
            /* Calculates the random displacement of the mouse cursor */
            dx = rand_approx_uniform(MIN_DIST_X, MAX_DIST_X);
            dy = rand_approx_uniform(MIN_DIST_Y, MAX_DIST_Y);
            if (is_rand_clicks)
            {
                moves_next_click--;

                /* Inject clicks, if CLICK_THRESHOLD moves, since last click */
                if (moves_next_click <= 0
                    && (oy + dy) < BOTTOM_THRES && (ox + dx) > LEFT_THRES)
                    is_click = true;
            }
        }
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

        if (is_click)
        {
            PRINT_DEBUG("[HIDSIM] [INJECTOR] Clicking now at %d x %d\n", ox, oy);
            is_click = false;
            click(qc, left);

            if (is_rand_clicks)
            {
                moves_next_click = gaussian_rand(CLK_MEAN, CLK_SIGMA);

                /* Simple heuristic for employing double clicks and keypresses */
                if (moves_next_click % 2 == 0)
                {
                    click(qc, left);
                }
            }
        }
        /* Gaussian distributed waiting between smooth movements */
        sleep = (int) gaussian_rand(0, 10000);

        if (sleep>0)
            usleep(sleep);

        s++;
    }

    return 0;
}

/*
 * Performs HID event injection according to pre-recorded Evdev-events
 * given by a binary file
 */
static int run_template_injection(qmp_connection* qc, FILE* f,
    std::atomic<bool>* has_to_stop)
{
    PRINT_DEBUG("[HIDSIM] [INJECTOR] Running template injection\n");

    /* Evdev events to inject */
    struct input_event ie_next, ie_cur;

    /* QMP-event representation of input_event */
    struct json_object* evt;
    struct json_object* events = json_object_new_array();

    /* Keeping track of time */
    struct timeval tv_old;
    struct timeval tv_diff;

    size_t nr = 0;
    long int sleep = 0;
    long int sleep_sanitized = 0;
    bool was_last = true;

    /* Reads first event */
    nr = fread(&ie_cur, sizeof(ie_cur), 1, f);

    if (nr != 1)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error reading first input event");
        return 1;
    }

    /* Waits until first event should be injected */
    sleep = ie_cur.time.tv_sec * 1000000 + ie_cur.time.tv_usec;

    /* Sanitizes potentially tainted data */
    sleep_sanitized = sleep > MAX_SLEEP ? MAX_SLEEP : sleep;
    usleep(sleep_sanitized);

    while (!has_to_stop->load())
    {
        /* Handles the special case of the first event */
        if (was_last)
        {
            /* Prepares injection by initializing all variables */
            if (reset_hid_injection(qc, f, &tv_old, &new_x, &new_y) != 0)
            {
                fprintf(stderr, "[HIDSIM] [INJECTOR] Error resetting HID injection");
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
            sleep = TIME_BIN + 1;
        }
        else
        {
            timersub(&ie_next.time, &ie_cur.time, &tv_diff);
            sleep = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
        }

        /* Converts evdev-event to qmp-string and appends it to buffer */
        evt = handle_event(&ie_cur);

        if (evt)
            json_object_array_add(events, evt);

        /*
         * Throttles event injection, by combing all events within a timeframe of 50 usecs
         * This performs actually a binning with bin size of 50 usecs
         */
        if (sleep > TIME_BIN)
        {
            /* Constructs execute-cmd containing various events */
            struct json_object* cmd = construct_input_event_cmd(events);

            /* Sends command */
            qmp_communicate_json(qc, cmd, NULL);
            PRINT_DEBUG("[HIDSIM] %s\n", json_object_to_json_string_ext(cmd,
                    JSON_C_TO_STRING_SPACED));

            /* Resets event buffer */
            json_object_put(cmd);
            events = json_object_new_array();
        }

        /* Omits sleeping after injection of last event */
        if (!was_last)
        {
            /* Sanitizes potentially tainted data */
            sleep_sanitized = sleep > MAX_SLEEP ? MAX_SLEEP : sleep;
            usleep(sleep_sanitized);

            /* Advances input event to process */
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
            fprintf(stderr, "[HIDSIM] [INJECTOR] Error closing QMP socket %s\n",
                qc->sa.sun_path);
    if (f)
        if ((ret = fclose(f)) != 0)
            fprintf(stderr, "[HIDSIM] [INJECTOR] Error closing stream\n");
    if (fd >= 0)
        if ((ret = close(fd)) != 0)
            fprintf(stderr, "[HIDSIM] [INJECTOR] Error closing %d\n", fd);

    return ret;
}

/* Worker thread function */
int hid_inject(const char* sock_path, const char* template_path, bool is_rand_clicks,
    std::atomic<uint32_t>* coords, std::atomic<bool>* has_to_stop)
{
    /* Initializes qmp connection */
    qmp_connection qc;
    int sc = 0;
    int fd = -1;
    FILE* f = NULL;

    if (qmp_init_conn(&qc, sock_path) < 0)
    {
        fprintf(stderr, "[HIDSIM] [INJECTOR] Could not connect to Unix Domain Socket %s.\n",
            sock_path);
        return 1;
    }

    if (template_path != NULL && strlen(template_path)>0)
    {
        fd = open(template_path, O_RDONLY);

        if (fd < 0)
        {
            fprintf(stderr, "[HIDSIM] [INJECTOR] Error opening file %s\n", template_path);
            hid_cleanup(&qc, fd, NULL);
            return 1;
        }

        /* Asks for aggressive readahead */
        if (posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL)!=0)
        {
            fprintf(stderr, "[HIDSIM] [INJECTOR] Asking for aggressive readahead on FD %d \
            failed. Continuing anyway...\n", fd);
        }

        f = fdopen(fd, "rb");

        if (!f)
        {
            fprintf(stderr, "[HIDSIM] [INJECTOR] Error reading from %s\n", template_path);
            hid_cleanup(&qc, fd, NULL);
            return 1;
        }

        if (read_header(f) != 0)
        {
            fprintf(stderr, "[HIDSIM] [INJECTOR] Not a valid HID template file. Stopping\n");
            hid_cleanup(&qc, fd, f);
            return 1;
        }

        /* Performs actual injection */
        sc = run_template_injection(&qc, f, has_to_stop);
    }
    else
    {
        sc = run_random_injection(&qc, is_rand_clicks, coords, has_to_stop);
    }
    if (sc != 0)
        fprintf(stderr, "[HIDSIM] [INJECTOR] Error performing HID injection\n");

    hid_cleanup(&qc, fd, f);

    return 0;
}
