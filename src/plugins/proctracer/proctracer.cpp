/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#include <glib.h>
#include <libvmi/libvmi.h>
#include "../plugins.h"
#include "private.h"
#include "proctracer.h"

enum offset {
    EPROCESS_PEB,
    EPROCESS_PID,
    LDR_DATA_TABLE_ENTRY_BASEDLLNAME,
    LDR_DATA_TABLE_ENTRY_DLLBASE,
    PEB_IMGBASE,
    __OFFSET_MAX
};

static const char *offset_names[__OFFSET_MAX][2] = {
    [EPROCESS_PEB] = {"_EPROCESS","Peb"},
    [EPROCESS_PID] = {"_EPROCESS","UniqueProcessId"},
    [LDR_DATA_TABLE_ENTRY_BASEDLLNAME] = { "_LDR_DATA_TABLE_ENTRY", "BaseDllName" },
    [LDR_DATA_TABLE_ENTRY_DLLBASE] = { "_LDR_DATA_TABLE_ENTRY", "DllBase" },
    [PEB_IMGBASE] = {"_PEB","ImageBaseAddress"}
};

struct trace_trap_struct{
    char* proc_name;
    addr_t pa;
    drakvuf_trap_t *trap;
};

static event_response_t trace_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info){
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    printf("[PROCTRACER] Trace point hit: 0x%lx\n",info->regs->rip);

    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    proctracer *p = (proctracer*)info->trap->data;
    if (p->trace_status.find(info->regs->cr3) == p->trace_status.end())
        return 0;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (p->trace_status.find(info->regs->cr3) == p->trace_status.end()){
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    list<mod_info*> *module_traps=p->trace_status[info->regs->cr3];
    for (mod_info* mi: *module_traps){
        printf("Removing traps from %s\n", mi->mod_name.c_str());        
        for (drakvuf_trap_t* dt: mi->traps){
            printf("Trap remove\n");
            drakvuf_remove_trap(drakvuf,dt,NULL);
        }
        /*printf("Deleting mod_name\n");
        delete mi->mod_name;
        printf("Deleting traps");
        delete mi->traps;*/
        //printf("Removing mod_info element\n");
        delete mi;
    }
    printf("Erasing trace status\n");
    p->trace_status.erase(info->regs->cr3);

/*    struct trace_trap_struct *tts = (struct trace_trap_struct*)g_hash_table_lookup(p->tracetraps, &info->regs->cr3);

    if (tts){

        printf("[PROCTRACER] Removing %s (%lx) from trace\n", tts->proc_name, info->regs->cr3);
        drakvuf_remove_trap(drakvuf,tts->trap,NULL);
        free(tts->proc_name);
        g_hash_table_remove(p->tracetraps,&info->regs->cr3);

    }
  */  
    drakvuf_release_vmi(drakvuf);
    return 0;
}

// Runs on PsGetCurrentThreadTeb (process context)
static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    proctracer *p = (proctracer*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t process = drakvuf_get_current_process(drakvuf, info->vcpu, info->regs);
    char *proc_name = drakvuf_get_process_name(drakvuf, process); 
    printf("[PROCTRACER] CR3: %lx NAME: %s\n", info->regs->cr3, proc_name);
    if (p->mod_config.find(proc_name) == p->mod_config.end()){
        free(proc_name);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    //addr_t base_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, get_process_base(vmi, process, p) + 0x5bfd0);
    //printf("[PROCTRACER] Base PA: %lx\n", base_pa);

    // [TODO] This is basically duplicate code from inject_traps_modules() - Maybe the library func should provide a callback parameter?

    addr_t module_list;
    bool traps_ok = drakvuf_get_module_list(drakvuf, process, &module_list);

    vmi_pid_t pid;

    if(VMI_FAILURE == vmi_read_32_va(vmi, process + p->offsets[EPROCESS_PID], 0, (uint32_t*)&pid)){
        printf("[PROCTRACER] Couldn't find PID!\n");
        traps_ok = false;
    }
    addr_t list_head = module_list;
    addr_t next_module = list_head;

    while (traps_ok) {
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next)
            break;

        addr_t dllbase = 0;
        vmi_read_addr_va(vmi, next_module + p->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase);

        if (!dllbase)
            break;

        unicode_string_t *us = vmi_read_unicode_str_va(vmi, next_module + p->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us) {
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            if(VMI_SUCCESS == status){
                printf("\t%s @ 0x%lx\n", out.contents, dllbase);
                if (p->mod_config.find((char*)out.contents) != p->mod_config.end()){
                    printf ("CAN TRAP THIS \\o/\n"); 
                    for (addr_t off: *p->mod_config[(char*)out.contents]){
                        printf("Offset: %lx",off);
                        mod_info *mi = new mod_info;
                        mi->mod_name=(char*)out.contents;
                        //mi->traps=new list<drakvuf_trap_t*>();
                        if (p->trace_status.find(info->regs->cr3) == p->trace_status.end()){
                            p->trace_status[info->regs->cr3]=new list<mod_info*>();

                        }

                        drakvuf_trap_t *maintrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
        
                        addr_t trap_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, dllbase+off);
                        maintrap->lookup_type = LOOKUP_NONE;
                        maintrap->addr_type = ADDR_PA;
                        maintrap->type = BREAKPOINT;
                        maintrap->name = "TraceTrap";
                        maintrap->cb = trace_cb;
                        maintrap->u2.addr = trap_pa;
                        maintrap->data = p;
                        
                        drakvuf_add_trap(drakvuf,maintrap);
                        mi->traps.insert(++(mi->traps.begin()),maintrap);

                        p->trace_status[info->regs->cr3]->insert(++(p->trace_status[info->regs->cr3]->end()),mi);
                    }
                }
            }
            vmi_free_unicode_str(us);
        }

        next_module = tmp_next;
    }  


    /*if (base_pa){
        trace_trap_struct *tts = (struct trace_trap_struct*)g_malloc0(sizeof(struct trace_trap_struct)); 
        printf("[PROCTRACER] Adding dynamic trap\n");
        //uint32_t mark;
        //vmi_read_32_pa(vmi,base_pa,&mark);
        //printf("Mark before: %lx\n",mark);
        drakvuf_trap_t *maintrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
        
        maintrap->lookup_type = LOOKUP_NONE;
        maintrap->addr_type = ADDR_PA;
        maintrap->type = BREAKPOINT;
        maintrap->name = "TraceTrap";
        maintrap->cb = trace_cb;
        maintrap->u2.addr = base_pa;
        maintrap->data = p;

        drakvuf_add_trap(drakvuf, maintrap);

        tts->pa = base_pa;
        tts->trap=maintrap;
        tts->proc_name=g_strdup(proc_name);
        g_hash_table_insert(p->tracetraps, &info->regs->cr3, tts);
    }else{
        printf("[PROCTRACER] Couldn't find physical address!\n");    
    }*/
    free(proc_name);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

proctracer::proctracer(drakvuf_t drakvuf, const void *config, output_format_t output) {
    const char *rekall_profile =(const char *)config;
    printf("[PROCTRACER] Starting...\n");

    this->offsets = (size_t*)g_malloc0(__OFFSET_MAX*sizeof(size_t));

    for(int i=0;i<__OFFSET_MAX;i++) {
        drakvuf_get_struct_member_rva(rekall_profile, offset_names[i][0], offset_names[i][1],
                                      &this->offsets[i]);
    }

    /* TESTING */

    list<addr_t> *cm_offsets=new list<addr_t>();
    cm_offsets->insert(++cm_offsets->end(),0x5bfd0);
    this->mod_config["CrashMe.exe"]=cm_offsets;

    /***********/

    this->tracetraps=g_hash_table_new(g_int64_hash, g_int64_equal);
    if(VMI_FAILURE == drakvuf_get_function_rva(rekall_profile, "PsGetCurrentThreadTeb", &this->trap.u2.rva))
        return;

    if(VMI_FAILURE == drakvuf_get_function_rva(rekall_profile, "PspExitProcess", &this->exit_trap.u2.rva))
        return;

    this->trap.cb = cb;
    this->trap.data = (void*)this;

    this->exit_trap.cb = exit_cb;
    this->exit_trap.data = (void*)this;

    this->format = output;

    if ( !drakvuf_add_trap(drakvuf,&this->trap) || !drakvuf_add_trap(drakvuf,&this->exit_trap))
        throw -1;
    printf("[PROCTRACER] Started successfully\n");
}

proctracer::~proctracer() {
    if (this->tracetraps){
        g_hash_table_destroy(this->tracetraps);    
    }

    for(const auto& n : this->mod_config){
        delete n.second;    
    } 

    /*for(const auto& n : this->trace_status){
        for (mod_info* mi: *n.second){
            //delete mi->mod_name;
            delete mi->traps;
        } 
        delete n.second;
    }*/
}
