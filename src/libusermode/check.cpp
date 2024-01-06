/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

#include "utils.hpp"
#include "printers/printers.hpp"
#include "userhook.hpp"

#include <sstream>
#include <string>

#include <check.h>

START_TEST(test_match_dll_name)
{
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.dll", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.DLL", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\MSI.DLL", "msi.dll"));
    ck_assert(!is_dll_name_matched("\\Windows\\System32\\amsi.dll", "msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\SysWOW64\\msi.dll", "syswow64\\msi.dll"));
    ck_assert(!is_dll_name_matched("\\Windows\\SysWOW64\\msi.dll", "wow64\\msi.dll"));
    ck_assert(is_dll_name_matched("\\Windows\\System32\\msi.dll", "\\Windows\\System32\\msi.dll"));
}
END_TEST

static Suite* dll_matching_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Match DLL names");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_match_dll_name);
    suite_add_tcase(s, tc_core);

    return s;
}

static plugin_target_config_entry_t test_parse_dll_entry(const std::string& entry)
{
    PrinterConfig config;
    std::stringstream ss(entry);
    return parse_entry(ss, config);
}

START_TEST(test_parse_dll_hook)
{
    auto entry_str = "combase.dll,CoCreateInstance,log,rclsid:refclsid,punkOuter:lpvoid,dwClsContext:dword,riid:refiid,ppv:void**";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "combase.dll");
    ck_assert(entry.function_name == "CoCreateInstance");
    ck_assert(entry.type == HOOK_BY_NAME);
    ck_assert(entry.clsid.empty());
    ck_assert(entry.offset == 0);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.size() == 5);
}
END_TEST

START_TEST(test_parse_dll_hook_with_offset)
{
    auto entry_str = "taskschd.dll,ITaskFolder::RegisterTaskDefinition,clsid,0F87369F-A4E5-4CFC-BD3E-73E6154572DD,13cd3,log,lpvoid,bstr";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "taskschd.dll");
    ck_assert(entry.function_name == "ITaskFolder::RegisterTaskDefinition");
    ck_assert(entry.type == HOOK_BY_OFFSET);
    ck_assert(entry.clsid == "0F87369F-A4E5-4CFC-BD3E-73E6154572DD");
    ck_assert(entry.offset == 0x13cd3);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.size() == 2);
}
END_TEST

START_TEST(test_parse_dll_hook_with_empty_args)
{
    auto entry_str = "combase.dll,CoCreateInstance,log";
    auto entry = test_parse_dll_entry(entry_str);

    ck_assert(entry.dll_name == "combase.dll");
    ck_assert(entry.function_name == "CoCreateInstance");
    ck_assert(entry.type == HOOK_BY_NAME);
    ck_assert(entry.clsid.empty());
    ck_assert(entry.offset == 0);
    ck_assert(!entry.no_retval);
    ck_assert(entry.actions.log && !entry.actions.stack);
    ck_assert(entry.argument_printers.empty());
}
END_TEST

static Suite* dll_hooks_parsing_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("Parse DLL hooks");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_parse_dll_hook);
    tcase_add_test(tc_core, test_parse_dll_hook_with_offset);
    tcase_add_test(tc_core, test_parse_dll_hook_with_empty_args);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = dll_matching_suite();
    sr = srunner_create(s);
    srunner_add_suite(sr, dll_hooks_parsing_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
