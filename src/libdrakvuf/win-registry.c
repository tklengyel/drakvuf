/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <glib.h>

#include "private.h"
#include "win-offsets.h"


char* drakvuf_reg_keycontrolblock_path( drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t p_key_control_block )
{
    status_t vmi_status ;
    addr_t p_name_control_block = 0 ;
    char* buf_ret ;
    vmi_instance_t vmi = drakvuf->vmi;
    access_context_t ctx =
    {
        .addr = p_key_control_block + drakvuf->offsets[ CM_KEY_NAMEBLOCK ],
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    vmi_status = vmi_read_addr( vmi, &ctx, (void*)&p_name_control_block );

    if ( ( vmi_status == VMI_SUCCESS ) && p_name_control_block )
    {
        uint16_t name_length = 0 ;

        ctx.addr = p_name_control_block + drakvuf->offsets[ CM_KEY_NAMELENGTH ] ;

        if ( vmi_read_16( vmi, &ctx, &name_length ) == VMI_SUCCESS )
        {
            if ( name_length && ( name_length < 240 ) )
            {
                buf_ret = (char*)g_malloc0( name_length + 1 );

                if ( buf_ret )
                {
                    ctx.addr = p_name_control_block + drakvuf->offsets[ CM_KEY_NAMEBUFFER] ;

                    if ( VMI_SUCCESS == vmi_read( vmi, &ctx, name_length, buf_ret, NULL ) )
                    {
                        int i ;

                        for ( i=0 ; i< name_length ; i++ )
                        {
                            if ( ( buf_ret[ i ] < 32 ) || ( buf_ret[ i ] > 126 ) )
                                buf_ret[ i ] = '?' ;
                        }

                        buf_ret[ name_length ] = 0 ;

                        return buf_ret ;
                    }

                    g_free( buf_ret );
                }
            }
#ifdef DRAKVUF_DEBUG
            else
                PRINT_DEBUG( "Inconsistent registry key name length [%d]!!\n", name_length );
#endif
        }
    }

    return NULL ;
}


char* drakvuf_reg_keybody_path( drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t p_key_body )
{
    char* buf_ret = NULL ;
    status_t vmi_status ;
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t p_key_control_block = 0 ;
    access_context_t ctx =
    {
        .addr = p_key_body + drakvuf->offsets[ CM_KEY_CONTROL_BLOCK ],
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    vmi_status = vmi_read_addr( vmi, &ctx, &p_key_control_block );

    if ( ( vmi_status == VMI_SUCCESS ) && p_key_control_block )
    {
        GSList* key_path_list = NULL ;
        int tot_len = 0;

        while ( ( vmi_status == VMI_SUCCESS ) && p_key_control_block )
        {
            char* key_path = drakvuf_reg_keycontrolblock_path( drakvuf, info, p_key_control_block );

            if ( key_path )
            {
                key_path_list = g_slist_prepend( key_path_list, key_path );
                tot_len += strlen( key_path );
            }
            else
                break ;

            ctx.addr = p_key_control_block + drakvuf->offsets[ CM_KEY_PARENTKCB ] ;

            vmi_status = vmi_read_addr( vmi, &ctx, &p_key_control_block );
        }

        if ( tot_len )
        {
            tot_len += g_slist_length( key_path_list ) + 1 ;

            buf_ret = (char*)g_malloc0( tot_len ) ;

            if ( buf_ret )
            {
                GSList* iterator ;

                *buf_ret = 0 ;

                for ( iterator = key_path_list; iterator ; iterator = iterator->next )
                {
                    strcat( buf_ret, "\\" );
                    strcat( buf_ret, (char*)iterator->data );
                    g_free( iterator->data );
                }
            }
        }

        g_slist_free( key_path_list );
    }

    return buf_ret ;
}


char* drakvuf_reg_keyhandle_path( drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t key_handle, addr_t process_arg )
{
    addr_t process = process_arg ;

    if ( ! process )
        process = drakvuf_get_current_process( drakvuf, info->vcpu );

    if ( process )
    {
        addr_t obj = drakvuf_get_obj_by_handle( drakvuf, process, key_handle );

        if ( obj )
        {
            // TODO: Check if object type is REG_KEY
            addr_t p_key_body = obj + drakvuf->offsets[OBJECT_HEADER_BODY];

            if ( p_key_body )
                return drakvuf_reg_keybody_path( drakvuf, info, p_key_body );
        }
    }

    return NULL ;
}

