#include "printers.hpp"
#include <string>
#include <iomanip>
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>

std::string ArgumentPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument)
{
    std::stringstream stream;
    stream << "0x" << std::hex << argument;
    return stream.str();
}

std::string AsciiPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument)
{
    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    };
    char *str = vmi_read_str(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);
    std::stringstream stream;
    stream << "0x" << std::hex << argument << ":\"" << str << "\""; // TODO base64? so it doesn't break JSON?
    return stream.str();
}

std::string WideStringPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument)
{
    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    };
    auto str_obj = drakvuf_read_wchar_string(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);
    char *str = str_obj == NULL ? NULL : (char*)str_obj->contents;
    size_t len = str_obj == NULL ? 0 : str_obj->length;
    std::stringstream stream;
    stream << "0x" << std::hex << argument << ": " << len << " \"" << str << "\""; // TODO base64? so it doesn't break JSON?
    return stream.str();
}

BitMaskPrinter::BitMaskPrinter(std::map < uint64_t, std::string > dict) : dict(dict)
{}

std::string BitMaskPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument)
{
    std::stringstream stream;
    stream << "0x" << std::hex << argument << ": ";
    if (argument == 0 && this->dict.find(0) != this->dict.end())
    {
        stream << this->dict[0];
    }
    else
    {
        bool first = true;
        for (std::pair<uint64_t, std::string> element : this->dict)
        {
            if (argument & element.first)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    stream << " | ";
                }
                stream << element.second;
            }
        }
    }
    return stream.str();
}

