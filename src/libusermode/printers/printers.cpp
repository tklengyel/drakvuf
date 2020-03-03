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

std::string StringPrinterInterface::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument)
{
    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    };
    std::string str = getBuffer(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);
    std::stringstream stream;
    stream << "0x" << std::hex << argument << ":\"" << str << "\"";
    return stream.str();
}

std::string AsciiPrinter::getBuffer(vmi_instance_t vmi, const access_context_t* ctx)
{
    char *str = vmi_read_str(vmi, ctx);
    return str ? str : "";
}

std::string WideStringPrinter::getBuffer(vmi_instance_t vmi, const access_context_t* ctx)
{
    auto str_obj = drakvuf_read_wchar_string(vmi, ctx);
    return str_obj == NULL ? "" : (char*)str_obj->contents;
}

std::string UnicodePrinter::getBuffer(vmi_instance_t vmi, const access_context_t* ctx)
{
    auto str_obj = drakvuf_read_unicode_common(vmi, ctx);
    return str_obj == NULL ? "" : (char*)str_obj->contents;
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
