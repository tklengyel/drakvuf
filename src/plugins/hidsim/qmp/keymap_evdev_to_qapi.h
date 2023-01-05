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
 * This file was created by Jan Gruber.                                    *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/
#ifndef KEYMAP_EVDEV_TO_QAPI_H
#define KEYMAP_EVDEV_TO_QAPI_H
/*
 * Qemu's keycode mapping is defined within the following tabular file:
 * https://github.com/qemu/keycodemapdb/blob/master/data/keymaps.csv
 *
 * This mapping can be automatically generated by keymap-gen and the a/m
 * .csv-file by utilizing the following commands:
 *
 *      git clone git@github.com:qemu/keycodemapdb.git
 *      python ./tools/keymap-gen name-map ./data/keymaps.csv linux qcode
 *      keymap-gen name-map --lang=stdc keymaps.csv linux qcode
 *
 * Indexes in the array are values from the source code set
 * Entries in the array are names from the target code set
 */
const char* name_map_linux_to_qcode[525] =
{
    [0x0] = "unmapped",          /* linux:0 (KEY_RESERVED) -> linux:0 (KEY_RESERVED) -> qcode:unmapped (unmapped) */
    [0x1] = "esc",               /* linux:1 (KEY_ESC) -> linux:1 (KEY_ESC) -> qcode:esc (esc) */
    [0x2] = "1",                 /* linux:2 (KEY_1) -> linux:2 (KEY_1) -> qcode:1 (1) */
    [0x3] = "2",                 /* linux:3 (KEY_2) -> linux:3 (KEY_2) -> qcode:2 (2) */
    [0x4] = "3",                 /* linux:4 (KEY_3) -> linux:4 (KEY_3) -> qcode:3 (3) */
    [0x5] = "4",                 /* linux:5 (KEY_4) -> linux:5 (KEY_4) -> qcode:4 (4) */
    [0x6] = "5",                 /* linux:6 (KEY_5) -> linux:6 (KEY_5) -> qcode:5 (5) */
    [0x7] = "6",                 /* linux:7 (KEY_6) -> linux:7 (KEY_6) -> qcode:6 (6) */
    [0x8] = "7",                 /* linux:8 (KEY_7) -> linux:8 (KEY_7) -> qcode:7 (7) */
    [0x9] = "8",                 /* linux:9 (KEY_8) -> linux:9 (KEY_8) -> qcode:8 (8) */
    [0xa] = "9",                 /* linux:10 (KEY_9) -> linux:10 (KEY_9) -> qcode:9 (9) */
    [0xb] = "0",                 /* linux:11 (KEY_0) -> linux:11 (KEY_0) -> qcode:0 (0) */
    [0xc] = "minus",             /* linux:12 (KEY_MINUS) -> linux:12 (KEY_MINUS) -> qcode:minus (minus) */
    [0xd] = "equal",             /* linux:13 (KEY_EQUAL) -> linux:13 (KEY_EQUAL) -> qcode:equal (equal) */
    [0xe] = "backspace",         /* linux:14 (KEY_BACKSPACE) -> linux:14 (KEY_BACKSPACE) -> qcode:backspace (backspace) */
    [0xf] = "tab",               /* linux:15 (KEY_TAB) -> linux:15 (KEY_TAB) -> qcode:tab (tab) */
    [0x10] = "q",                /* linux:16 (KEY_Q) -> linux:16 (KEY_Q) -> qcode:q (q) */
    [0x11] = "w",                /* linux:17 (KEY_W) -> linux:17 (KEY_W) -> qcode:w (w) */
    [0x12] = "e",                /* linux:18 (KEY_E) -> linux:18 (KEY_E) -> qcode:e (e) */
    [0x13] = "r",                /* linux:19 (KEY_R) -> linux:19 (KEY_R) -> qcode:r (r) */
    [0x14] = "t",                /* linux:20 (KEY_T) -> linux:20 (KEY_T) -> qcode:t (t) */
    [0x15] = "y",                /* linux:21 (KEY_Y) -> linux:21 (KEY_Y) -> qcode:y (y) */
    [0x16] = "u",                /* linux:22 (KEY_U) -> linux:22 (KEY_U) -> qcode:u (u) */
    [0x17] = "i",                /* linux:23 (KEY_I) -> linux:23 (KEY_I) -> qcode:i (i) */
    [0x18] = "o",                /* linux:24 (KEY_O) -> linux:24 (KEY_O) -> qcode:o (o) */
    [0x19] = "p",                /* linux:25 (KEY_P) -> linux:25 (KEY_P) -> qcode:p (p) */
    [0x1a] = "bracket_left",     /* linux:26 (KEY_LEFTBRACE) -> linux:26 (KEY_LEFTBRACE) -> qcode:bracket_left (bracket_left) */
    [0x1b] = "bracket_right",    /* linux:27 (KEY_RIGHTBRACE) -> linux:27 (KEY_RIGHTBRACE) -> qcode:bracket_right (bracket_right) */
    [0x1c] = "ret",              /* linux:28 (KEY_ENTER) -> linux:28 (KEY_ENTER) -> qcode:ret (ret) */
    [0x1d] = "ctrl",             /* linux:29 (KEY_LEFTCTRL) -> linux:29 (KEY_LEFTCTRL) -> qcode:ctrl (ctrl) */
    [0x1e] = "a",                /* linux:30 (KEY_A) -> linux:30 (KEY_A) -> qcode:a (a) */
    [0x1f] = "s",                /* linux:31 (KEY_S) -> linux:31 (KEY_S) -> qcode:s (s) */
    [0x20] = "d",                /* linux:32 (KEY_D) -> linux:32 (KEY_D) -> qcode:d (d) */
    [0x21] = "f",                /* linux:33 (KEY_F) -> linux:33 (KEY_F) -> qcode:f (f) */
    [0x22] = "g",                /* linux:34 (KEY_G) -> linux:34 (KEY_G) -> qcode:g (g) */
    [0x23] = "h",                /* linux:35 (KEY_H) -> linux:35 (KEY_H) -> qcode:h (h) */
    [0x24] = "j",                /* linux:36 (KEY_J) -> linux:36 (KEY_J) -> qcode:j (j) */
    [0x25] = "k",                /* linux:37 (KEY_K) -> linux:37 (KEY_K) -> qcode:k (k) */
    [0x26] = "l",                /* linux:38 (KEY_L) -> linux:38 (KEY_L) -> qcode:l (l) */
    [0x27] = "semicolon",        /* linux:39 (KEY_SEMICOLON) -> linux:39 (KEY_SEMICOLON) -> qcode:semicolon (semicolon) */
    [0x28] = "apostrophe",       /* linux:40 (KEY_APOSTROPHE) -> linux:40 (KEY_APOSTROPHE) -> qcode:apostrophe (apostrophe) */
    [0x29] = "grave_accent",     /* linux:41 (KEY_GRAVE) -> linux:41 (KEY_GRAVE) -> qcode:grave_accent (grave_accent) */
    [0x2a] = "shift",            /* linux:42 (KEY_LEFTSHIFT) -> linux:42 (KEY_LEFTSHIFT) -> qcode:shift (shift) */
    [0x2b] = "backslash",        /* linux:43 (KEY_BACKSLASH) -> linux:43 (KEY_BACKSLASH) -> qcode:backslash (backslash) */
    [0x2c] = "z",                /* linux:44 (KEY_Z) -> linux:44 (KEY_Z) -> qcode:z (z) */
    [0x2d] = "x",                /* linux:45 (KEY_X) -> linux:45 (KEY_X) -> qcode:x (x) */
    [0x2e] = "c",                /* linux:46 (KEY_C) -> linux:46 (KEY_C) -> qcode:c (c) */
    [0x2f] = "v",                /* linux:47 (KEY_V) -> linux:47 (KEY_V) -> qcode:v (v) */
    [0x30] = "b",                /* linux:48 (KEY_B) -> linux:48 (KEY_B) -> qcode:b (b) */
    [0x31] = "n",                /* linux:49 (KEY_N) -> linux:49 (KEY_N) -> qcode:n (n) */
    [0x32] = "m",                /* linux:50 (KEY_M) -> linux:50 (KEY_M) -> qcode:m (m) */
    [0x33] = "comma",            /* linux:51 (KEY_COMMA) -> linux:51 (KEY_COMMA) -> qcode:comma (comma) */
    [0x34] = "dot",              /* linux:52 (KEY_DOT) -> linux:52 (KEY_DOT) -> qcode:dot (dot) */
    [0x35] = "slash",            /* linux:53 (KEY_SLASH) -> linux:53 (KEY_SLASH) -> qcode:slash (slash) */
    [0x36] = "shift_r",          /* linux:54 (KEY_RIGHTSHIFT) -> linux:54 (KEY_RIGHTSHIFT) -> qcode:shift_r (shift_r) */
    [0x37] = "kp_multiply",      /* linux:55 (KEY_KPASTERISK) -> linux:55 (KEY_KPASTERISK) -> qcode:kp_multiply (kp_multiply) */
    [0x38] = "alt",              /* linux:56 (KEY_LEFTALT) -> linux:56 (KEY_LEFTALT) -> qcode:alt (alt) */
    [0x39] = "spc",              /* linux:57 (KEY_SPACE) -> linux:57 (KEY_SPACE) -> qcode:spc (spc) */
    [0x3a] = "caps_lock",        /* linux:58 (KEY_CAPSLOCK) -> linux:58 (KEY_CAPSLOCK) -> qcode:caps_lock (caps_lock) */
    [0x3b] = "f1",               /* linux:59 (KEY_F1) -> linux:59 (KEY_F1) -> qcode:f1 (f1) */
    [0x3c] = "f2",               /* linux:60 (KEY_F2) -> linux:60 (KEY_F2) -> qcode:f2 (f2) */
    [0x3d] = "f3",               /* linux:61 (KEY_F3) -> linux:61 (KEY_F3) -> qcode:f3 (f3) */
    [0x3e] = "f4",               /* linux:62 (KEY_F4) -> linux:62 (KEY_F4) -> qcode:f4 (f4) */
    [0x3f] = "f5",               /* linux:63 (KEY_F5) -> linux:63 (KEY_F5) -> qcode:f5 (f5) */
    [0x40] = "f6",               /* linux:64 (KEY_F6) -> linux:64 (KEY_F6) -> qcode:f6 (f6) */
    [0x41] = "f7",               /* linux:65 (KEY_F7) -> linux:65 (KEY_F7) -> qcode:f7 (f7) */
    [0x42] = "f8",               /* linux:66 (KEY_F8) -> linux:66 (KEY_F8) -> qcode:f8 (f8) */
    [0x43] = "f9",               /* linux:67 (KEY_F9) -> linux:67 (KEY_F9) -> qcode:f9 (f9) */
    [0x44] = "f10",              /* linux:68 (KEY_F10) -> linux:68 (KEY_F10) -> qcode:f10 (f10) */
    [0x45] = "num_lock",         /* linux:69 (KEY_NUMLOCK) -> linux:69 (KEY_NUMLOCK) -> qcode:num_lock (num_lock) */
    [0x46] = "scroll_lock",      /* linux:70 (KEY_SCROLLLOCK) -> linux:70 (KEY_SCROLLLOCK) -> qcode:scroll_lock (scroll_lock) */
    [0x47] = "kp_7",             /* linux:71 (KEY_KP7) -> linux:71 (KEY_KP7) -> qcode:kp_7 (kp_7) */
    [0x48] = "kp_8",             /* linux:72 (KEY_KP8) -> linux:72 (KEY_KP8) -> qcode:kp_8 (kp_8) */
    [0x49] = "kp_9",             /* linux:73 (KEY_KP9) -> linux:73 (KEY_KP9) -> qcode:kp_9 (kp_9) */
    [0x4a] = "kp_subtract",      /* linux:74 (KEY_KPMINUS) -> linux:74 (KEY_KPMINUS) -> qcode:kp_subtract (kp_subtract) */
    [0x4b] = "kp_4",             /* linux:75 (KEY_KP4) -> linux:75 (KEY_KP4) -> qcode:kp_4 (kp_4) */
    [0x4c] = "kp_5",             /* linux:76 (KEY_KP5) -> linux:76 (KEY_KP5) -> qcode:kp_5 (kp_5) */
    [0x4d] = "kp_6",             /* linux:77 (KEY_KP6) -> linux:77 (KEY_KP6) -> qcode:kp_6 (kp_6) */
    [0x4e] = "kp_add",           /* linux:78 (KEY_KPPLUS) -> linux:78 (KEY_KPPLUS) -> qcode:kp_add (kp_add) */
    [0x4f] = "kp_1",             /* linux:79 (KEY_KP1) -> linux:79 (KEY_KP1) -> qcode:kp_1 (kp_1) */
    [0x50] = "kp_2",             /* linux:80 (KEY_KP2) -> linux:80 (KEY_KP2) -> qcode:kp_2 (kp_2) */
    [0x51] = "kp_3",             /* linux:81 (KEY_KP3) -> linux:81 (KEY_KP3) -> qcode:kp_3 (kp_3) */
    [0x52] = "kp_0",             /* linux:82 (KEY_KP0) -> linux:82 (KEY_KP0) -> qcode:kp_0 (kp_0) */
    [0x53] = "kp_decimal",       /* linux:83 (KEY_KPDOT) -> linux:83 (KEY_KPDOT) -> qcode:kp_decimal (kp_decimal) */
    [0x56] = "less",             /* linux:86 (KEY_102ND) -> linux:86 (KEY_102ND) -> qcode:less (less) */
    [0x57] = "f11",              /* linux:87 (KEY_F11) -> linux:87 (KEY_F11) -> qcode:f11 (f11) */
    [0x58] = "f12",              /* linux:88 (KEY_F12) -> linux:88 (KEY_F12) -> qcode:f12 (f12) */
    [0x59] = "ro",               /* linux:89 (KEY_RO) -> linux:89 (KEY_RO) -> qcode:ro (ro) */
    [0x5b] = "hiragana",         /* linux:91 (KEY_HIRAGANA) -> linux:91 (KEY_HIRAGANA) -> qcode:hiragana (hiragana) */
    [0x5c] = "henkan",           /* linux:92 (KEY_HENKAN) -> linux:92 (KEY_HENKAN) -> qcode:henkan (henkan) */
    [0x5d] = "katakanahiragana", /* linux:93 (KEY_KATAKANAHIRAGANA) -> linux:93 (KEY_KATAKANAHIRAGANA) -> qcode:katakanahiragana (katakanahiragana) */
    [0x5e] = "muhenkan",         /* linux:94 (KEY_MUHENKAN) -> linux:94 (KEY_MUHENKAN) -> qcode:muhenkan (muhenkan) */
    [0x60] = "kp_enter",         /* linux:96 (KEY_KPENTER) -> linux:96 (KEY_KPENTER) -> qcode:kp_enter (kp_enter) */
    [0x61] = "ctrl_r",           /* linux:97 (KEY_RIGHTCTRL) -> linux:97 (KEY_RIGHTCTRL) -> qcode:ctrl_r (ctrl_r) */
    [0x62] = "kp_divide",        /* linux:98 (KEY_KPSLASH) -> linux:98 (KEY_KPSLASH) -> qcode:kp_divide (kp_divide) */
    [0x63] = "sysrq",            /* linux:99 (KEY_SYSRQ) -> linux:99 (KEY_SYSRQ) -> qcode:sysrq (sysrq) */
    [0x64] = "alt_r",            /* linux:100 (KEY_RIGHTALT) -> linux:100 (KEY_RIGHTALT) -> qcode:alt_r (alt_r) */
    [0x65] = "lf",               /* linux:101 (KEY_LINEFEED) -> linux:101 (KEY_LINEFEED) -> qcode:lf (lf) */
    [0x66] = "home",             /* linux:102 (KEY_HOME) -> linux:102 (KEY_HOME) -> qcode:home (home) */
    [0x67] = "up",               /* linux:103 (KEY_UP) -> linux:103 (KEY_UP) -> qcode:up (up) */
    [0x68] = "pgup",             /* linux:104 (KEY_PAGEUP) -> linux:104 (KEY_PAGEUP) -> qcode:pgup (pgup) */
    [0x69] = "left",             /* linux:105 (KEY_LEFT) -> linux:105 (KEY_LEFT) -> qcode:left (left) */
    [0x6a] = "right",            /* linux:106 (KEY_RIGHT) -> linux:106 (KEY_RIGHT) -> qcode:right (right) */
    [0x6b] = "end",              /* linux:107 (KEY_END) -> linux:107 (KEY_END) -> qcode:end (end) */
    [0x6c] = "down",             /* linux:108 (KEY_DOWN) -> linux:108 (KEY_DOWN) -> qcode:down (down) */
    [0x6d] = "pgdn",             /* linux:109 (KEY_PAGEDOWN) -> linux:109 (KEY_PAGEDOWN) -> qcode:pgdn (pgdn) */
    [0x6e] = "insert",           /* linux:110 (KEY_INSERT) -> linux:110 (KEY_INSERT) -> qcode:insert (insert) */
    [0x6f] = "delete",           /* linux:111 (KEY_DELETE) -> linux:111 (KEY_DELETE) -> qcode:delete (delete) */
    [0x71] = "audiomute",        /* linux:113 (KEY_MUTE) -> linux:113 (KEY_MUTE) -> qcode:audiomute (audiomute) */
    [0x72] = "volumedown",       /* linux:114 (KEY_VOLUMEDOWN) -> linux:114 (KEY_VOLUMEDOWN) -> qcode:volumedown (volumedown) */
    [0x73] = "volumeup",         /* linux:115 (KEY_VOLUMEUP) -> linux:115 (KEY_VOLUMEUP) -> qcode:volumeup (volumeup) */
    [0x74] = "power",            /* linux:116 (KEY_POWER) -> linux:116 (KEY_POWER) -> qcode:power (power) */
    [0x75] = "kp_equals",        /* linux:117 (KEY_KPEQUAL) -> linux:117 (KEY_KPEQUAL) -> qcode:kp_equals (kp_equals) */
    [0x77] = "pause",            /* linux:119 (KEY_PAUSE) -> linux:119 (KEY_PAUSE) -> qcode:pause (pause) */
    [0x79] = "kp_comma",         /* linux:121 (KEY_KPCOMMA) -> linux:121 (KEY_KPCOMMA) -> qcode:kp_comma (kp_comma) */
    [0x7c] = "yen",              /* linux:124 (KEY_YEN) -> linux:124 (KEY_YEN) -> qcode:yen (yen) */
    [0x7d] = "meta_l",           /* linux:125 (KEY_LEFTMETA) -> linux:125 (KEY_LEFTMETA) -> qcode:meta_l (meta_l) */
    [0x7e] = "meta_r",           /* linux:126 (KEY_RIGHTMETA) -> linux:126 (KEY_RIGHTMETA) -> qcode:meta_r (meta_r) */
    [0x7f] = "compose",          /* linux:127 (KEY_COMPOSE) -> linux:127 (KEY_COMPOSE) -> qcode:compose (compose) */
    [0x80] = "stop",             /* linux:128 (KEY_STOP) -> linux:128 (KEY_STOP) -> qcode:stop (stop) */
    [0x81] = "again",            /* linux:129 (KEY_AGAIN) -> linux:129 (KEY_AGAIN) -> qcode:again (again) */
    [0x82] = "props",            /* linux:130 (KEY_PROPS) -> linux:130 (KEY_PROPS) -> qcode:props (props) */
    [0x83] = "undo",             /* linux:131 (KEY_UNDO) -> linux:131 (KEY_UNDO) -> qcode:undo (undo) */
    [0x84] = "front",            /* linux:132 (KEY_FRONT) -> linux:132 (KEY_FRONT) -> qcode:front (front) */
    [0x85] = "copy",             /* linux:133 (KEY_COPY) -> linux:133 (KEY_COPY) -> qcode:copy (copy) */
    [0x86] = "open",             /* linux:134 (KEY_OPEN) -> linux:134 (KEY_OPEN) -> qcode:open (open) */
    [0x87] = "paste",            /* linux:135 (KEY_PASTE) -> linux:135 (KEY_PASTE) -> qcode:paste (paste) */
    [0x88] = "find",             /* linux:136 (KEY_FIND) -> linux:136 (KEY_FIND) -> qcode:find (find) */
    [0x89] = "cut",              /* linux:137 (KEY_CUT) -> linux:137 (KEY_CUT) -> qcode:cut (cut) */
    [0x8a] = "help",             /* linux:138 (KEY_HELP) -> linux:138 (KEY_HELP) -> qcode:help (help) */
    [0x8b] = "menu",             /* linux:139 (KEY_MENU) -> linux:139 (KEY_MENU) -> qcode:menu (menu) */
    [0x8c] = "calculator",       /* linux:140 (KEY_CALC) -> linux:140 (KEY_CALC) -> qcode:calculator (calculator) */
    [0x8e] = "sleep",            /* linux:142 (KEY_SLEEP) -> linux:142 (KEY_SLEEP) -> qcode:sleep (sleep) */
    [0x8f] = "wake",             /* linux:143 (KEY_WAKEUP) -> linux:143 (KEY_WAKEUP) -> qcode:wake (wake) */
    [0x9b] = "mail",             /* linux:155 (KEY_MAIL) -> linux:155 (KEY_MAIL) -> qcode:mail (mail) */
    [0x9c] = "ac_bookmarks",     /* linux:156 (KEY_BOOKMARKS) -> linux:156 (KEY_BOOKMARKS) -> qcode:ac_bookmarks (ac_bookmarks) */
    [0x9d] = "computer",         /* linux:157 (KEY_COMPUTER) -> linux:157 (KEY_COMPUTER) -> qcode:computer (computer) */
    [0x9e] = "ac_back",          /* linux:158 (KEY_BACK) -> linux:158 (KEY_BACK) -> qcode:ac_back (ac_back) */
    [0x9f] = "ac_forward",       /* linux:159 (KEY_FORWARD) -> linux:159 (KEY_FORWARD) -> qcode:ac_forward (ac_forward) */
    [0xa3] = "audionext",        /* linux:163 (KEY_NEXTSONG) -> linux:163 (KEY_NEXTSONG) -> qcode:audionext (audionext) */
    [0xa4] = "audioplay",        /* linux:164 (KEY_PLAYPAUSE) -> linux:164 (KEY_PLAYPAUSE) -> qcode:audioplay (audioplay) */
    [0xa5] = "audioprev",        /* linux:165 (KEY_PREVIOUSSONG) -> linux:165 (KEY_PREVIOUSSONG) -> qcode:audioprev (audioprev) */
    [0xa6] = "audiostop",        /* linux:166 (KEY_STOPCD) -> linux:166 (KEY_STOPCD) -> qcode:audiostop (audiostop) */
    [0xac] = "ac_home",          /* linux:172 (KEY_HOMEPAGE) -> linux:172 (KEY_HOMEPAGE) -> qcode:ac_home (ac_home) */
    [0xad] = "ac_refresh",       /* linux:173 (KEY_REFRESH) -> linux:173 (KEY_REFRESH) -> qcode:ac_refresh (ac_refresh) */
    [0xe2] = "mediaselect",      /* linux:226 (KEY_MEDIA) -> linux:226 (KEY_MEDIA) -> qcode:mediaselect (mediaselect) */
};
const unsigned int name_map_linux_to_qcode_len = sizeof(name_map_linux_to_qcode) / sizeof(name_map_linux_to_qcode[0]);

#endif
