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
#include "writer.h"

#include "drakvuf.h"

#include <zlib.h>

#include <string>
#include <cstdio>
#include <cstdint>

namespace
{

class BaseProcdumpWriter : public ProcdumpWriter
{
public:
    explicit BaseProcdumpWriter(std::string const& path)
        : file{fopen(path.c_str(), "w")}
    {
        if (!file) throw -1;
    }

    ~BaseProcdumpWriter()
    {
        fclose(file);
    }

    bool append(uint8_t const* data, size_t size) override
    {
        return (size == 0 || fwrite(data, size, 1, file) == 1);
    }

    bool finish() override
    {
        return (fflush(file) == 0);
    }

private:
    FILE* file;
};

class GzippedProcdumpWriter : public BaseProcdumpWriter
{
public:
    explicit GzippedProcdumpWriter(std::string const& path)
        : BaseProcdumpWriter{path}
        , z_file{}
    {
        z_file.zalloc = Z_NULL;
        z_file.zfree = Z_NULL;
        z_file.opaque = Z_NULL;
        z_file.avail_in = 0;
        z_file.next_in = Z_NULL;
        int window_bits = 15 + 16; // Use gzip header format with windowbits of 15
        int mem_level = 8;
        auto ret = deflateInit2(&z_file, Z_BEST_SPEED, Z_DEFLATED, window_bits, mem_level, Z_DEFAULT_STRATEGY);
        if (ret != Z_OK) throw -1;
    }

    ~GzippedProcdumpWriter()
    {
        deflateEnd(&z_file);
    }

    bool append(uint8_t const* data, size_t size) override
    {
        z_file.avail_in = size;
        z_file.next_in = const_cast<uint8_t*>(data);
        return write_impl(Z_NO_FLUSH);
    }

    bool finish() override
    {
        return write_impl(Z_FINISH) && BaseProcdumpWriter::finish();
    }

private:
    bool write_impl(int flush);

private:
    z_stream z_file;
};

bool GzippedProcdumpWriter::write_impl(int flush)
{
    do
    {
        uint8_t out[16 * 1024];
        z_file.avail_out = sizeof(out);
        z_file.next_out = out;

        auto ret = deflate(&z_file, flush);
        if (ret == Z_STREAM_ERROR)
        {
            PRINT_DEBUG("[PROCDUMP] GZIP fail: deflate return Z_STREAM_ERROR");
            return false;
        }

        if (!BaseProcdumpWriter::append(out, sizeof(out) - z_file.avail_out)) return false;
    } while (z_file.avail_out == 0);
    if (z_file.avail_in != 0)
    {
        PRINT_DEBUG("[PROCDUMP] GZIP fail: z_file.avail_in != 0");
        return false;
    }
    return true;
}

}

std::unique_ptr<ProcdumpWriter> ProcdumpWriterFactory::build(std::string const& path, bool use_compression)
{
    if (use_compression) return std::make_unique<GzippedProcdumpWriter>(path);
    return std::make_unique<BaseProcdumpWriter>(path);
}
