/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
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

#ifndef STRUCTURES_H
#define STRUCTURES_H

/******************************************/

#define LIBXL_API_VERSION 0x040300
#define INVALID_DOMID ~(uint32_t)0

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
//#include <libxl.h>
#include <libxl_utils.h>
#include <xenctrl.h>
//#include <xenstore.h>

#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#ifdef HAVE_XMLRPC
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#endif

typedef struct xen_interface {
  //struct xs_handle *xsh;
  xc_interface *xc;
  libxl_ctx *xl_ctx;
  xentoollog_logger *xl_logger;
} xen_interface_t;

typedef struct log_interface {

  pthread_mutex_t log_IDX_lock;
  uint32_t log_IDX;

  pthread_mutex_t mysql_lock;
  bool mysql_enabled;
  char* mysql_address;
  char* mysql_user;
  char* mysql_pass;
  char* mysql_db;
  uint32_t mysql_port;

#ifdef HAVE_MYSQL
  MYSQL* mysql_conn;
#endif

} honeymon_log_interface_t;

typedef struct honeymon {

  GMutex lock;

  xen_interface_t* xen;
  honeymon_log_interface_t* log;

  bool stealthy;
  bool interactive;
  uint32_t action;
  char* action_option;

  char* workdir;
  char* originsdir;
  char* honeypotsdir;
  char* backupdir;
  char* virusdir;

  GTree* honeypots; // a tree of honeymon_honeypot_t's
  uint16_t vlans :12; //vlan id

  // clone factory
  GAsyncQueue *clone_requests;
  pthread_t clone_factory;

  GTree *pooltags;
  GTree *guids;

#ifdef HAVE_XMLRPC
  GMutex rpc_lock;
  GCond rpc_cond;
  pthread_t rpc_server_thread;

  xmlrpc_server_abyss_t *rpc_server;
#endif

#ifdef HAVE_LIBMAGIC
  magic_t magic_cookie;
#endif

} honeymon_t;

/* These structs are opaque in xlu but we need them
 * to parse the configuration files. */
typedef struct {
  struct XLU_ConfigList2 *next;
  char *name;
  int nvalues, avalues; /* lists have avalues>1 */
  char **values;
  int lineno;
} XLU_ConfigList2;

typedef struct {
  XLU_ConfigList2 *settings;
  FILE *report;
  char *config_source;
} XLU_Config2;

typedef struct honeypot {

  GMutex lock;

  char* name;
  char* snapshot_path;
  char* config_path;
  char* ip_path;

  // Rekall profile of the Kernel
  char *rekall_profile;
  struct sym_config *sym_config;

  XLU_Config2 *config;

  // network info
  char ip[INET_ADDRSTRLEN];
  char *mac;

  win_ver_t winver;

  unsigned int domID; // 0 if not actually running but restorable
  unsigned int clones; // number of active clones
  unsigned int max_clones; // max number of active clones
  unsigned int clone_buffer; // number of inactive clones to keep around at any time
  GTree* clone_list; // clone list of honeymon_clone_t

  GTree* fschecksum; // each node is a GTree with the file path as key and hash as value
} honeymon_honeypot_t;

struct symbol {
  char *name;
  addr_t rva;
  uint8_t type;
  int inputs;
} __attribute__ ((packed));

struct sym_config {
  char *name;
  //const char **guids;
  struct symbol *syms;
  uint64_t sym_count;
} __attribute__ ((packed));

/*struct guid_lookup {
  struct config *conf;
  GHashTable *rva_lookup;
  uint8_t free;
};*/

typedef struct clone {
  honeymon_t* honeymon;
  honeymon_honeypot_t* origin;
  char* origin_name;
  char* clone_name;
  char* config_path;

  char* disk_path;

  uint16_t vlan;
  uint32_t domID;
  uint32_t honeybridID;

  // thread stuff
  pthread_t signal_thread;
  pthread_t vmi_thread;

  GMutex lock;
  GMutex scan_lock;
  GCond cond;
  bool active;
  bool paused;

  // scan scheduling
  uint32_t nscans; // number of scans to be scheduled
  uint32_t cscan; // the scan to be scheduled next (cscan is always < nscans)
  uint32_t* tscan; // list of times to wait between scans
  pthread_t* scan_threads;
  bool* scan_results;
  uint32_t scan_initiator; //0=scheduled, 1=network event, 2=timeout

  // log IDX
  uint32_t logIDX;
  uint32_t start_time;

  GTimer *timer;

  // VMI
  int interrupted;
  page_mode_t pm;
  vmi_instance_t vmi;
  win_ver_t winver;
  GTree *guid_lookup; // key: both PE and PDB GUIDs
  GHashTable *pa_lookup; // key: PA of trap
  GHashTable *pool_lookup; // key: PA of trap
  GHashTable *file_watch;
  GSList *trap_reset;

  GHashTable *files_accessed;

} honeymon_clone_t;

//sID = 3
#define FILE_WATCH 3
struct file_watch {
  honeymon_clone_t *clone;
  addr_t file_base;
  addr_t file_name;
  addr_t obj;
}__attribute__ ((packed));

//sID = 2
#define POOL_LOOKUP 2
struct pool_lookup {
  uint8_t backup;
  union {
      unsigned char ctag[4];
      uint32_t tag;
  };
  reg_t cr3;
  uint32_t size;
  uint32_t count;
}__attribute__ ((packed));

//sID = 1
#define SYMBOLWRAP 1
struct symbolwrap {
  const struct sym_config *config;
  const struct symbol *symbol;
  uint8_t backup;
  honeymon_clone_t *clone;
}__attribute__ ((packed));

struct memevent {
  uint8_t sID;
  honeymon_clone_t *clone;
  vmi_instance_t vmi;
  vmi_event_t *guard;
  addr_t pa;
  union {
      struct symbolwrap symbol;
      struct pool_lookup pool;
      struct file_watch file;
  };
}__attribute__ ((packed));

#endif
