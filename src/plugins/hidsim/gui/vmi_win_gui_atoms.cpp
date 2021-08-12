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

#include <stdio.h>

/* For PRINT_DEBUG */
#include "../../private.h"
/* For eprint_current_time  */
#include <libdrakvuf/libdrakvuf.h>

#include "vmi_win_gui_offsets.h"
#include "vmi_win_gui_utils.h"

extern struct Offsets symbol_offsets;

struct atom_entry
{
    uint16_t atom;
    uint16_t ref_count;
    addr_t hashlink;
    uint8_t name_len;
    wchar_t* name;
};

void free_atom_entry(struct atom_entry* a)
{
    if (a)
        free(a->name);

    free(a);
}

/* Prints a single atom entry */
void print_atom(gpointer key, gpointer value, gpointer user_data)
{
    PRINT_DEBUG("Atom: %" PRIx16 " %ls\n", GPOINTER_TO_UINT(key),
        ((struct atom_entry*)value)->name);
}

/*
 * Parses the in memory kernel data structure representing an atom entry and
 * stores the result in a struct of type atom_entry
 */
struct atom_entry* parse_atom_entry(vmi_instance_t vmi, addr_t atom_addr)
{
    struct atom_entry* entry;

    entry = (struct atom_entry*) calloc(1, sizeof(struct atom_entry));
    if (!entry)
    {
        printf("[HIDSIM][MONITOR] Memory allocation for atom entry failed\n");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_addr_va(vmi, atom_addr +
            symbol_offsets.atom_entry_hashlink_offset, 0, &entry->hashlink))
    {
        printf("Error reading HashLink at %" PRIx64 "\n", atom_addr +
            symbol_offsets.atom_entry_hashlink_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr +
            symbol_offsets.atom_entry_atom_offset, 0, &entry->atom))
    {
        printf("Error reading Atom at %" PRIx64 "\n", atom_addr +
            symbol_offsets.atom_entry_atom_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr +
            symbol_offsets.atom_entry_ref_count_offset, 0, &entry->ref_count))
    {
        printf("Error reading ReferenceCount at %" PRIx64 "\n", atom_addr +
            symbol_offsets.atom_entry_ref_count_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi, atom_addr +
            symbol_offsets.atom_entry_name_len_offset, 0, &entry->name_len))
    {
        printf("Error reading NameLength at %" PRIx64 "\n", atom_addr +
            symbol_offsets.atom_entry_name_len_offset);
        return NULL;
    }

    entry->name = read_wchar_str(vmi, atom_addr +
            symbol_offsets.atom_entry_name_offset, (size_t)entry->name_len);

    if (!entry->name)
    {
        printf("Error reading wchar-string Name at %" PRIx64 "\n", atom_addr +
            symbol_offsets.atom_entry_name_offset);
    }

    return entry;
}

/* Creates a single atom-entry struct */
struct atom_entry* create_atom_entry(uint16_t atom, const wchar_t* name,
    uint8_t len, addr_t hashlink, uint16_t refcount)
{
    struct atom_entry* entry;

    entry = (struct atom_entry*) calloc(1, sizeof(struct atom_entry));
    if (!entry)
    {
        printf("[HIDSIM][MONITOR] Memory allocation for atom entry failed\n");
        return NULL;
    }

    entry->atom = atom;
    entry->name = wcsdup(name);
    entry->name_len = len;
    entry->hashlink = hashlink;
    entry->ref_count = refcount;

    return entry;
}

/*
 * Adds the default _RTL_ATOM_ENTRY-structs to the atom-table
 *
 * Default _RTL_ATOM_ENTRY-structs
 * See https://github.com/volatilityfoundation/volatility/blob/\
 * a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/\
 * constants.py#L34
 */
void add_default_atoms(GHashTable* atom_table)
{
    struct atom_entry* ae = NULL;

    ae = create_atom_entry(0x8000, L"PopupMenu", 9, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

    ae = create_atom_entry(0x8001, L"Desktop", 7, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

    ae = create_atom_entry(0x8002, L"Dialog", 6, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

    ae = create_atom_entry(0x8003, L"WinSwitch", 9, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

    ae = create_atom_entry(0x8004, L"IconTitle", 9, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

    ae = create_atom_entry(0x8006, L"ToolTip", 9, 0, 0);
    g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae->atom), (gpointer)ae);

}

/*
 * Builds up the atom table, which serves as a shared resource hosting class
 * IDs and their name (regularily used by more than one process)
 *
 * Additional background information can be found at:
 * https://bsodtutorials.wordpress.com/2015/11/11/understanding-atom-tables/
 */
GHashTable* build_atom_table(vmi_instance_t vmi, addr_t table_addr)
{
    uint32_t num_buckets = 0;

    if (VMI_FAILURE == vmi_read_32_va(vmi, table_addr +
            symbol_offsets.atom_table_num_buckets_off, 0, &num_buckets))
    {
        printf("Failed to read num buckets-value of _RTL_ATOM_TABLE at %" PRIx64
            "\n", table_addr + symbol_offsets.atom_table_num_buckets_off);
        return NULL;
    }

    GHashTable* ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
            (GDestroyNotify) free_atom_entry);
    add_default_atoms(ht);

    size_t i = 0;
    addr_t cur = 0;
    struct atom_entry* a = NULL;

    /* Iterate the array of pointers to _RTL_ATOM_TABLE_ENTRY-structs at buckets */
    while (i < num_buckets)
    {
        if (VMI_FAILURE == vmi_read_addr_va(vmi, table_addr +
                symbol_offsets.atom_table_buckets_off + i * 4, 0, &cur))
        {
            printf("Failed to read pointer to buckets entry of _RTL_ATOM_TABLE at %"
                PRIx64 "\n", table_addr + symbol_offsets.atom_table_buckets_off + i * 4);
            g_hash_table_destroy(ht);
            return NULL;
        }
        i++;

        if (!cur)
            continue;

        a = parse_atom_entry(vmi, cur);

        if (a)
        {
            g_hash_table_insert(ht, GUINT_TO_POINTER(a->atom), (gpointer)a);
        }

        /* Traverses the linked list of each top level _RTL_ATOM_TABLE_ENTRY */
        while (a && a->hashlink)
        {
            cur = a->hashlink;
            a = parse_atom_entry(vmi, cur);

            if (a)
            {
                g_hash_table_insert(ht, GUINT_TO_POINTER(a->atom), (gpointer)a);
            }
        }
    }

    return ht;
}
