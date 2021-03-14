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
 ***************************************************************************/

#include <unistd.h>
#include <limits.h>

#include <iostream>
#include <sstream>
#include <string>

#include <librepl/librepl.h>
#include <Python.h>

#ifdef DRAKVUF_DEBUG

extern bool verbose;

#define PRINT_DEBUG(args...) \
    do { \
        if(verbose) fprintf (stderr, args); \
    } while (0)

#else
#define PRINT_DEBUG(args...) \
    do {} while(0)
#endif

#define Py_REF_DEBUG \
    PyObject* refCount = PyObject_CallObject(PySys_GetObject("gettotalrefcount"), NULL); \
    PRINT_DEBUG("total refcount = %i\n", PyInt_AsSsize_t(refCount)); \
    Py_DECREF(refCount);

static std::string get_selfpath()
{
    char buf[PATH_MAX];
    ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1)
    {
        buf[len] = '\0';
        return std::string(buf);
    }
    else
    {
        PRINT_DEBUG("failed to get executable path!");
        exit(1);
    }
}

static event_response_t get_ret_val()
{
    // Using PyEval_GetGlobals would probably be nicer, but it returned nullptr
    auto module = PyImport_AddModule("__main__");
    auto retval = PyLong_AsSize_t(PyObject_GetAttrString(module, "retval"));
    PRINT_DEBUG("retval: %lu\n", retval);
    return static_cast<event_response_t>(retval);
}

static void repl_init(drakvuf_t drakvuf)
{
    // init python
    Py_Initialize();

    // get executable path
    auto exe_path = get_selfpath();
    auto py_drakvuf_path = exe_path.substr(0, exe_path.find_last_of('/')) + "/librepl";
    PRINT_DEBUG("PyDrakvuf path: %s\n", py_drakvuf_path.c_str());

    // load libdrakvuf
    auto sysPath = PySys_GetObject("path");
    PyList_Append(sysPath, PyUnicode_FromString(py_drakvuf_path.c_str()));
    auto module = PyImport_ImportModule("libdrakvuf");

    if (module == NULL)
    {
        std::cout << "No libdrakvuf.py found, please generate it before running REPL\n";
        exit(1);
    }

    // import modules
    if (PyRun_SimpleString("from ctypes import *\nimport IPython\nimport libdrakvuf\n") == -1)
    {
        std::cout << "Failed to load one of dependencies\n";
        PyErr_Print();
        exit(1);
    }

    PyObject_SetAttrString(module, "drakvuf", PyLong_FromVoidPtr(static_cast<void*>(drakvuf)));
}

event_response_t repl_start(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    repl_init(drakvuf);

    std::cout << "=================================================================\n"
        << "REPL STARTING...\n"
        << "=================================================================\n";

    {
        std::stringstream ss;

        // convenient variable assignment
        ss << "trap_info = cast(" << static_cast<void*>(info) << ", POINTER(libdrakvuf.drakvuf_trap_info_t))\n";

        // pass repl_start to python
        ss << "trap_cb = CFUNCTYPE(libdrakvuf.event_response_t, libdrakvuf.drakvuf_t, POINTER(libdrakvuf.drakvuf_trap_info_t))\n";
        ss << "repl_start = cast(" << reinterpret_cast<void*>(repl_start) << ", trap_cb)\n";
        ss << "drakvuf = cast(" << reinterpret_cast<void*>(drakvuf) << ", libdrakvuf.drakvuf_t)\n";
        ss << "retval = " << reinterpret_cast<int>(VMI_EVENT_RESPONSE_NONE) << "\n";

        PRINT_DEBUG("setting up variables:\n%s", ss.str().c_str());

        PyRun_SimpleString(ss.str().c_str());
    }

    PyRun_SimpleString(
        "IPython.embed(colors='neutral', banner2=\"\"\""
        "REPL ready to go, enjoy hacking!\n"
        "trap_info contains current trap info structure\n"
        "drakvuf contains drakvuf_t pointer\n"
        "retval contains event return code, which you can overwrite\n"
        "to go back to drakvuf loop use exit(), to break loop use CTRL+C\"\"\")\n"
    );

    return get_ret_val();
}
