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

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>

#include "private.h"
#include "win_acl.h"
#include "plugins/private.h"

using std::hex;
using std::showbase;
using std::setfill;
using std::setw;
using std::string;
using std::stringstream;
using namespace filetracer_ns;

namespace
{

enum
{
    ACCESS_ALLOWED_ACE_TYPE                 = 0x0,
    ACCESS_DENIED_ACE_TYPE                  = 0x1,
    SYSTEM_AUDIT_ACE_TYPE                   = 0x2,
    SYSTEM_ALARM_ACE_TYPE                   = 0x3,
    // ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x4,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x5,
    ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x6,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x7,
    SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x8,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x9,
    ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0xA,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0xC,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0xD,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0xE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0xF,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 0x12,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 0x13,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE     = 0x14,
    SYSTEM_ACCESS_FILTER_ACE_TYPE           = 0x15,
};

#define REGISTER_ACE_PARSER(ACE) \
            case ACE##_TYPE: {\
                auto ace = reinterpret_cast<const struct ACE*>(header); \
                type = #ACE "_TYPE"; \
                mask = parse_flags(ace->Mask, generic_ar, format); \
                auto bytes_left = aces.get() + aces_size - ace_ptr - offsetof(struct ACE, SidStart); \
                sid = parse_sid(ace_ptr + offsetof(struct ACE, SidStart), bytes_left); \
                break; }\

static const flags_str_t ace_types =
{
    REGISTER_FLAG(ACCESS_ALLOWED_ACE_TYPE),
    REGISTER_FLAG(ACCESS_DENIED_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_AUDIT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_ALARM_ACE_TYPE),
    REGISTER_FLAG(ACCESS_ALLOWED_OBJECT_ACE_TYPE),
    REGISTER_FLAG(ACCESS_DENIED_OBJECT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_AUDIT_OBJECT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_ALARM_OBJECT_ACE_TYPE),
    REGISTER_FLAG(ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
    REGISTER_FLAG(ACCESS_DENIED_CALLBACK_ACE_TYPE),
    REGISTER_FLAG(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
    REGISTER_FLAG(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_ALARM_CALLBACK_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_MANDATORY_LABEL_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE),
    REGISTER_FLAG(SYSTEM_ACCESS_FILTER_ACE_TYPE),
};

enum
{
    OBJECT_INHERIT_ACE                = 0x1,
    CONTAINER_INHERIT_ACE             = 0x2,
    NO_PROPAGATE_INHERIT_ACE          = 0x4,
    INHERIT_ONLY_ACE                  = 0x8,
    INHERITED_ACE                     = 0x10,
    VALID_INHERIT_FLAGS               = 0x1F,
    CRITICAL_ACE_FLAG                 = 0x20,
    SUCCESSFUL_ACCESS_ACE_FLAG        = 0x40,
    FAILED_ACCESS_ACE_FLAG            = 0x80,
    TRUST_PROTECTED_FILTER_ACE_FLAG   = 0x40,
};

static const flags_str_t ace_flags =
{
    REGISTER_FLAG(OBJECT_INHERIT_ACE),
    REGISTER_FLAG(CONTAINER_INHERIT_ACE),
    REGISTER_FLAG(NO_PROPAGATE_INHERIT_ACE),
    REGISTER_FLAG(INHERIT_ONLY_ACE),
    REGISTER_FLAG(INHERITED_ACE),
    REGISTER_FLAG(VALID_INHERIT_FLAGS),
    REGISTER_FLAG(CRITICAL_ACE_FLAG),
    REGISTER_FLAG(SUCCESSFUL_ACCESS_ACE_FLAG),
    REGISTER_FLAG(FAILED_ACCESS_ACE_FLAG),
    REGISTER_FLAG(TRUST_PROTECTED_FILTER_ACE_FLAG),
};

using SID_IDENTIFIER_AUTHORITY = uint8_t[6];

struct SID
{
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    uint32_t SubAuthority[];
} __attribute__((packed, aligned(4)));

struct ACE_HEADER
{
    uint8_t  type;
    uint8_t  flags;
    uint16_t size;
} __attribute__((packed, aligned(4)));

using ACCESS_MASK = uint32_t;

struct GUID
{
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} __attribute__((packed, aligned(4)));

struct ACCESS_ALLOWED_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct ACCESS_DENIED_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_AUDIT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_ALARM_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Sid followed by CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
} __attribute__((packed, aligned(4)));

struct SYSTEM_SCOPED_POLICY_ID_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_MANDATORY_LABEL_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_PROCESS_TRUST_LABEL_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_ACCESS_FILTER_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Filter Condition follows the SID
} __attribute__((packed, aligned(4)));

struct ACCESS_ALLOWED_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct ACCESS_DENIED_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_AUDIT_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct SYSTEM_ALARM_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
} __attribute__((packed, aligned(4)));

struct ACCESS_ALLOWED_CALLBACK_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct ACCESS_DENIED_CALLBACK_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct SYSTEM_AUDIT_CALLBACK_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct SYSTEM_ALARM_CALLBACK_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
{
    struct ACE_HEADER Header;
    ACCESS_MASK Mask;
    uint32_t Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    uint32_t SidStart;
    // Opaque resource manager specific data
} __attribute__((packed, aligned(4)));

std::map<std::string, std::string> known_sids
{
    {"S-1-0-0", "Null SID"},
    {"S-1-1-0", "World"},
    {"S-1-2-0", "Local"},
    {"S-1-3-0", "Creator Owner ID"},
    {"S-1-3-1", "Creator Group ID"},
    {"S-1-3-2", "Creator Owner Server ID"},
    {"S-1-3-3", "Creator Group Server ID"},
    {"S-1-5-1", "Dialup"},
    {"S-1-5-2", "Network"},
    {"S-1-5-3", "Batch"},
    {"S-1-5-4", "Interactive"},
    {"S-1-5-6", "Service"},
    {"S-1-5-7", "AnonymousLogon"},
    {"S-1-5-8", "Proxy"},
    {"S-1-5-9", "Enterprise DC (EDC)"},
    {"S-1-5-10", "Self"},
    {"S-1-5-11", "Authenticated User"},
    {"S-1-5-12", "Restricted Code"},
    {"S-1-5-13", "Terminal Server"},
    {"S-1-5-14", "Remote Logon"},
    {"S-1-5-15", "This Organization"},
    {"S-1-5-17", "IUser"},
    {"S-1-5-19", "Local Service"},
    {"S-1-5-20", "Network Service"},
    {"S-1-5-64-10", "NTLM Authentication"},
    {"S-1-5-64-14", "SChannel Authentication"},
    {"S-1-5-64-21", "Digest Authentication"},
};

} // namespace

std::string parse_sid(const uint8_t buffer[], uint64_t buffer_size)
{
    if (buffer_size < 8)
    {
        PRINT_DEBUG("[FILETRACER] Invalid SID size\n");
        return std::string();
    }

    auto sid = reinterpret_cast<const struct SID*>(buffer);
    auto rev = static_cast<int>(sid->Revision);
    uint64_t id_auth = 0;
    for (uint64_t i = 0; i != sizeof(SID_IDENTIFIER_AUTHORITY); ++i)
    {
        uint64_t idx = sizeof(SID_IDENTIFIER_AUTHORITY) - 1 - i;
        uint64_t offset = i * sizeof(uint8_t);
        id_auth += ((uint64_t)sid->IdentifierAuthority[idx]) << offset;
    }

    std::stringstream fmt;
    fmt << "S-" << rev << "-" << id_auth;

    for (size_t i = 0; i != sid->SubAuthorityCount; ++i)
    {
        uint64_t delta = (const char*)&sid->SubAuthority[i] + sizeof(sid->SubAuthority[i]) - (const char*)buffer;
        if (delta > buffer_size)
        {
            PRINT_DEBUG("[FILETRACER] Invalid SID size\n");
            break;
        }

        fmt << "-" << sid->SubAuthority[i];
    }

    auto known_sid = known_sids.find(fmt.str());
    if (known_sids.cend() != known_sid)
        return known_sid->second;
    return fmt.str();
}

std::string read_sid(vmi_instance_t vmi, access_context_t* ctx, size_t* offsets)
{
    auto psid = ctx->addr;

    uint8_t count = 0;
    ctx->addr = psid + offsets[_SID_SubAuthorityCount];
    if ( VMI_SUCCESS != vmi_read_8(vmi, ctx, &count) )
        return std::string();

    auto sid_size = sizeof(struct SID) + sizeof(uint32_t)*count;
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[sid_size] {0});
    ctx->addr = psid;
    size_t bytes_read = 0;
    if ( VMI_SUCCESS != vmi_read(vmi, ctx, sid_size, buffer.get(), &bytes_read) ||
        sid_size != bytes_read)
        return string();

    return parse_sid(buffer.get(), sid_size);
}

string read_acl(vmi_instance_t vmi, access_context_t* ctx, size_t* offsets, string base_name, output_format_t format)
{
    stringstream fmt;

    const addr_t pacl = ctx->addr;

    size_t ace_count = 0;
    ctx->addr = pacl + offsets[_ACL_AceCount];
    if ( VMI_SUCCESS != vmi_read_8(vmi, ctx, reinterpret_cast<uint8_t*>(&ace_count)) || 0 == ace_count)
        return std::string();

    const size_t ACL_SIZE = 8;
    uint8_t acl_size = 0;
    ctx->addr = pacl + offsets[_ACL_AclSize];
    if ( VMI_SUCCESS != vmi_read_8(vmi, ctx, &acl_size) || ACL_SIZE >= acl_size )
        return std::string();

    const uint8_t aces_size = acl_size - ACL_SIZE;
    std::unique_ptr<uint8_t[]> aces(new uint8_t[aces_size] {0});
    auto ace_ptr = aces.get();
    ctx->addr = pacl + ACL_SIZE;
    size_t bytes_read = 0;
    if ( VMI_SUCCESS != vmi_read(vmi, ctx, aces_size, ace_ptr, &bytes_read) ||
        aces_size != bytes_read)
        return string();

    // manual work done, may arise issues
    switch (format)
    {
        case OUTPUT_CSV:
            fmt << '"';
            break;

        case OUTPUT_KV:
            fmt << base_name << '=' << ace_count;
            break;

        case OUTPUT_JSON:
            fmt << '"' << base_name << "\": [";
            break;

        default:
        case OUTPUT_DEFAULT:
            for (auto& c: base_name) c = std::toupper(c);
            fmt << base_name << "_COUNT:" << ace_count;
            break;
    }

    size_t aces_read = 0;
    while (ace_ptr < aces.get() + aces_size && aces_read < ace_count)
    {
        auto header = reinterpret_cast<const struct ACE_HEADER*>(ace_ptr);
        auto ace_size = static_cast<size_t>(header->size);
        string type;
        string mask;
        string sid;

        switch (header->type)
        {
                REGISTER_ACE_PARSER(ACCESS_ALLOWED_ACE)
                REGISTER_ACE_PARSER(ACCESS_DENIED_ACE)
                REGISTER_ACE_PARSER(SYSTEM_AUDIT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_ALARM_ACE)
                REGISTER_ACE_PARSER(ACCESS_ALLOWED_OBJECT_ACE)
                REGISTER_ACE_PARSER(ACCESS_DENIED_OBJECT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_AUDIT_OBJECT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_ALARM_OBJECT_ACE)
                REGISTER_ACE_PARSER(ACCESS_ALLOWED_CALLBACK_ACE)
                REGISTER_ACE_PARSER(ACCESS_DENIED_CALLBACK_ACE)
                REGISTER_ACE_PARSER(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE)
                REGISTER_ACE_PARSER(ACCESS_DENIED_CALLBACK_OBJECT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_AUDIT_CALLBACK_ACE)
                REGISTER_ACE_PARSER(SYSTEM_ALARM_CALLBACK_ACE)
                REGISTER_ACE_PARSER(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_ALARM_CALLBACK_OBJECT_ACE)
                REGISTER_ACE_PARSER(SYSTEM_MANDATORY_LABEL_ACE)
                REGISTER_ACE_PARSER(SYSTEM_RESOURCE_ATTRIBUTE_ACE)
                REGISTER_ACE_PARSER(SYSTEM_SCOPED_POLICY_ID_ACE)
                REGISTER_ACE_PARSER(SYSTEM_PROCESS_TRUST_LABEL_ACE)
                REGISTER_ACE_PARSER(SYSTEM_ACCESS_FILTER_ACE)

            default:
                break;
        }

        // manual work done, may arise issues
        switch (format)
        {
            case OUTPUT_CSV:
                if (ace_ptr != aces.get())
                    fmt << ',';
                fmt << type << ',' << hex << showbase << mask << ',' << sid;
                break;

            case OUTPUT_KV:
                fmt << ",Type=\"" << type << "\"";
                if (!mask.empty())
                    fmt << "," << hex << showbase << mask;
                fmt << ",SID=\"" << sid << '"';
                break;

            case OUTPUT_JSON:
                if (ace_ptr != aces.get())
                    fmt << ',';
                fmt << "{\"Type\" : \"" << type << "\",\"AccessMask\" : \"" << hex << showbase << mask << "\",\"SID\" : \"" << sid << "\"}";
                break;

            default:
            case OUTPUT_DEFAULT:
                fmt << ",TYPE:" << type << ",ACCESS_MASK:\"" << hex << showbase << mask << "\",SID:" << sid;;
                break;
        }

        if (0 == ace_size || ace_ptr + ace_size < ace_ptr)
        {
            PRINT_DEBUG("WARNING! Incorrect ACE size %ld\n", ace_size);
            break;
        }

        ace_ptr += ace_size;
        aces_read += 1;
    }

    // manual work done, may arise issues
    switch (format)
    {
        case OUTPUT_CSV:
            fmt << '"';
            break;

        case OUTPUT_JSON:
            fmt << ']';
            break;

        default:
        case OUTPUT_KV:
        case OUTPUT_DEFAULT:
            break;
    }

    return fmt.str();
}
