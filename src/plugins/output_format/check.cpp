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
***************************************************************************/

#include "common.h"
#include "kvfmt.h"
#include "jsonfmt.h"

#include <check.h>
#include <string>
#include <vector>

START_TEST(test_kvfmt_qstr_basic)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("simple"), ',');
    ck_assert_msg(ss.str() == std::string("\"simple\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_quoted)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("\"quoted\""), ',');
    ck_assert_msg(ss.str() == std::string("\"\\\"quoted\\\"\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_multiline)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("line 1\r\nline 2"), ',');
    ck_assert_msg(ss.str() == std::string("\"line 1\\r\\nline 2\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_windows_path)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("C:\\Windows"), ',');
    ck_assert_msg(ss.str() == std::string("\"C:\\Windows\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_utf_8)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("простая строка"), ',');
    ck_assert_msg(ss.str() == std::string("\"простая строка\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_utf_8_multiline)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("строка 1\r\nстрока 2"), ',');
    ck_assert_msg(ss.str() == std::string("\"строка 1\\r\\nстрока 2\""), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_qstr_utf_8_binary)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Qstr("простая строка \x1f"), ',');
    ck_assert_msg(ss.str() == std::string("\"простая строка \\x1F\""), "Get: %s", ss.str().data());
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_rstr_basic)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Rstr("simple"), ',');
    ck_assert_msg(ss.str() == std::string("simple"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_binary_string_basic)
{
    std::stringstream ss;
    bool result = false;

    const char* str = "\x1ftest";
    size_t str_len = strlen(str);

    result = kvfmt::print_data(ss, fmt::BinaryString(reinterpret_cast<const uint8_t*>(str), str_len), ',');
    ck_assert_msg(ss.str() == std::string("1f74657374"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_xval)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Xval(0xA1), ',');
    ck_assert_msg(ss.str() == std::string("0xA1"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_nval)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Nval(1), ',');
    ck_assert_msg(ss.str() == std::string("1"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_fval)
{
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, fmt::Fval(1.1), ',');
    ck_assert_msg(ss.str() == std::string("1.100000"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_timeval)
{
    TimeVal tv;
    tv.tv_sec = 1;
    tv.tv_usec = 1;
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, tv, ',');
    ck_assert_msg(ss.str() == std::string("1.000001"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_function_printer)
{
    std::stringstream ss;
    bool result = false;

    auto printer = [](std::ostream& os)
    {
        os << "x";
        return true;
    };
    result = kvfmt::print_data(ss, printer, ',');
    ck_assert_msg(ss.str() == std::string("x"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_optional)
{
    std::optional<fmt::Nval<int>> opt1;
    std::optional<fmt::Nval<int>> opt2{1};
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, opt1, ',');
    ck_assert_msg(ss.str() == std::string(""), nullptr);
    ck_assert_msg(result == false, nullptr);

    result = kvfmt::print_data(ss, opt2, ',');
    ck_assert_msg(ss.str() == std::string("1"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_pair_basic)
{
    std::pair<const char*, fmt::Nval<int>> data("x", 1);
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, data, ',');
    ck_assert_msg(ss.str() == std::string("x=1"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_pair_iterable)
{
    std::vector<fmt::Nval<int>> value{1, 2, 3};
    std::pair<const char*, std::vector<fmt::Nval<int>>> data("x", value);
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, data, ',');
    ck_assert_msg(ss.str() != std::string("x=1,2,3"), nullptr);
    ck_assert_msg(ss.str() == std::string("1,2,3"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_tuple)
{
    std::tuple<fmt::Nval<int>, fmt::Rstr<const char*>> t1{1, "x"};
    std::stringstream ss;
    bool result = false;

    result = kvfmt::print_data(ss, t1, ',');
    ck_assert_msg(ss.str() == std::string("1,x"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_variant)
{
    std::variant<fmt::Nval<int>, fmt::Rstr<const char*>> v{1};
    std::stringstream ss1, ss2;
    bool result = false;

    result = kvfmt::print_data(ss1, v, ',');
    ck_assert_msg(ss1.str() == std::string("1"), nullptr);
    ck_assert_msg(result == true, nullptr);

    v = "x";
    result = kvfmt::print_data(ss2, v, ',');
    ck_assert_msg(ss2.str() == std::string("x"), nullptr);
    ck_assert_msg(result == true, nullptr);
}
END_TEST

START_TEST(test_kvfmt_flags)
{
    std::stringstream ss;

    auto flags = flagsval("Flags", "FLAG_1=1,FLAG_2=1,FLAG_5=1");
    bool result = kvfmt::print_data(ss, flags, ',');

    ck_assert(ss.str() == "FLAG_1=1,FLAG_2=1,FLAG_5=1");
    ck_assert(result);
}
END_TEST

START_TEST(test_kvfmt_hier_flags)
{
    std::stringstream ss;

    std::vector<flagsval> security_descriptor;
    security_descriptor.emplace_back(flagsval("Control", "CONTROL1=1,CONTROL2=1"));
    security_descriptor.emplace_back(flagsval("Sacl", "SASL1=1,SASL4=1"));

    auto value = keyval("SecurityDescriptor", security_descriptor);
    bool result = kvfmt::print_data(ss, value, ',');

    ck_assert(ss.str() == "CONTROL1=1,CONTROL2=1,SASL1=1,SASL4=1");
    ck_assert(result);
}
END_TEST

START_TEST(test_jsonfmt_flags)
{
    std::stringstream ss;

    auto flags = flagsval("Flags", "FLAG_1|FLAG_2|FLAG_5");
    bool result = jsonfmt::print_data(ss, ',', flags);

    ck_assert(ss.str() == "{\"Flags\":\"FLAG_1|FLAG_2|FLAG_5\"}");
    ck_assert(result);
}
END_TEST

START_TEST(test_jsonfmt_hier_flags)
{
    std::stringstream ss;

    std::vector<flagsval> security_descriptor;
    security_descriptor.emplace_back(flagsval("Control", "CONTROL1|CONTROL2"));
    security_descriptor.emplace_back(flagsval("Sacl", "SASL1|SASL4"));

    auto value = keyval("SecurityDescriptor", security_descriptor);
    bool result = jsonfmt::print_data(ss, ',', value);

    ck_assert(ss.str() == "{\"SecurityDescriptor\":[{\"Control\":\"CONTROL1|CONTROL2\"},{\"Sacl\":\"SASL1|SASL4\"}]}");
    ck_assert(result);
}
END_TEST

Suite* kvfmt_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("KVFMT");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_kvfmt_qstr_basic);
    tcase_add_test(tc_core, test_kvfmt_qstr_quoted);
    tcase_add_test(tc_core, test_kvfmt_qstr_multiline);
    tcase_add_test(tc_core, test_kvfmt_qstr_windows_path);
    tcase_add_test(tc_core, test_kvfmt_qstr_utf_8);
    tcase_add_test(tc_core, test_kvfmt_qstr_utf_8_multiline);
    tcase_add_test(tc_core, test_kvfmt_qstr_utf_8_binary);
    tcase_add_test(tc_core, test_kvfmt_rstr_basic);
    tcase_add_test(tc_core, test_kvfmt_binary_string_basic);
    tcase_add_test(tc_core, test_kvfmt_xval);
    tcase_add_test(tc_core, test_kvfmt_nval);
    tcase_add_test(tc_core, test_kvfmt_fval);
    tcase_add_test(tc_core, test_kvfmt_timeval);
    tcase_add_test(tc_core, test_kvfmt_function_printer);
    tcase_add_test(tc_core, test_kvfmt_optional);
    tcase_add_test(tc_core, test_kvfmt_pair_basic);
    tcase_add_test(tc_core, test_kvfmt_pair_iterable);
    tcase_add_test(tc_core, test_kvfmt_tuple);
    tcase_add_test(tc_core, test_kvfmt_variant);
    tcase_add_test(tc_core, test_kvfmt_flags);
    tcase_add_test(tc_core, test_kvfmt_hier_flags);

    suite_add_tcase(s, tc_core);

    return s;
}

static Suite* jsonfmt_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("JSONFMT");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_jsonfmt_flags);
    tcase_add_test(tc_core, test_jsonfmt_hier_flags);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    SRunner* sr;

    sr = srunner_create(kvfmt_suite());
    srunner_add_suite(sr, jsonfmt_suite());

    // Uncomment if you want to see STDOUT
    //srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
