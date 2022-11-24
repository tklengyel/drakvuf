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
#pragma once

enum
{
    NDIS_PROTOCOL_BLOCK_NAME,
    NDIS_PROTOCOL_BLOCK_OPENQUEUE,
    NDIS_PROTOCOL_BLOCK_NEXTPROTOCOL,
    NDIS_OPEN_BLOCK_ROOTDEVICENAME,
    NDIS_OPEN_BLOCK_PROTOCOLNEXTOPEN,
    NDIS_OPEN_BLOCK_MINIPORTHANDLE,
    NDIS_MINIPORT_BLOCK_MINIPORTNAME,
    NDIS_MINIPORT_BLOCK_NEXTGLOBALMINIPORT,
    __OFFSET_GENERIC_MAX
};

enum 
{
    NDIS_OPEN_BLOCK_SENDHANDLER,
    NDIS_OPEN_BLOCK_WANSENDHANDLER,
    NDIS_OPEN_BLOCK_TRANSFERDATAHANDLER,
    NDIS_OPEN_BLOCK_SENDCOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_TRANSFERDATACOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_RECEIVEHANDLER,
    NDIS_OPEN_BLOCK_RECEIVECOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_WANRECEIVEHANDLER,
    NDIS_OPEN_BLOCK_REQUESTCOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_RECEIVEPACKETHANDLER,
    NDIS_OPEN_BLOCK_SENDPACKETSHANDLER,
    NDIS_OPEN_BLOCK_RESETHANDLER,
    NDIS_OPEN_BLOCK_REQUESTHANDLER,
    NDIS_OPEN_BLOCK_OIDREQUESTHANDLER,
    NDIS_OPEN_BLOCK_RESETCOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_STATUSHANDLER,
    NDIS_OPEN_BLOCK_STATUSHANDLEREX,
    NDIS_OPEN_BLOCK_STATUSCOMPLETEHANDLER,
    NDIS_OPEN_BLOCK_PROTSENDNETBUFFERLISTSCOMPLETE,
    NDIS_OPEN_BLOCK_RECEIVENETBUFFERLISTS,
    NDIS_OPEN_BLOCK_SAVEDSENDPACKETSHANDLER,
    NDIS_OPEN_BLOCK_SAVEDCANCELSENDPACKETSHANDLER,
    NDIS_OPEN_BLOCK_SAVEDSENDHANDLER,
    __OFFSET_OPEN_MAX
};

enum
{
    NDIS_MINIPORT_BLOCK_NEXTCANCELSENDNETBUFFERLISTSHANDLER,
    NDIS_MINIPORT_BLOCK_PACKETINDICATEHANDLER,
    NDIS_MINIPORT_BLOCK_SENDCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_SENDRESOURCESHANDLER,
    NDIS_MINIPORT_BLOCK_RESETCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_DISABLEINTERRUPTHANDLER,
    NDIS_MINIPORT_BLOCK_ENABLEINTERRUPTHANDLER,
    NDIS_MINIPORT_BLOCK_SENDPACKETSHANDLER,
    NDIS_MINIPORT_BLOCK_DEFERREDSENDHANDLER,
    NDIS_MINIPORT_BLOCK_ETHRXINDICATEHANDLER,
    NDIS_MINIPORT_BLOCK_NEXTSENDNETBUFFERLISTSHANDLER,
    NDIS_MINIPORT_BLOCK_ETHRXCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_SAVEDNEXTSENDNETBUFFERLISTSHANDLER,
    NDIS_MINIPORT_BLOCK_STATUSHANDLER,
    NDIS_MINIPORT_BLOCK_STATUSCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_TDCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_QUERYCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_SETCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_WANSENDCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_WANRCVHANDLER,
    NDIS_MINIPORT_BLOCK_WANRCVCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_SENDNETBUFFERLISTSCOMPLETEHANDLER,
    NDIS_MINIPORT_BLOCK_SAVEDPACKETINDICATEHANDLER,
    NDIS_MINIPORT_BLOCK_NEXTSENDPACKETSHANDLER,
    NDIS_MINIPORT_BLOCK_FINALSENDPACKETSHANDLER,
    NDIS_MINIPORT_BLOCK_SHUTDOWNHANDLER,
    NDIS_MINIPORT_BLOCK_TOPINDICATENETBUFFERLISTSHANDLER,
    NDIS_MINIPORT_BLOCK_TOPINDICATELOOPBACKNETBUFFERLISTSHANDLER,
    NDIS_MINIPORT_BLOCK_NDIS5PACKETINDICATEHANDLER,
    NDIS_MINIPORT_BLOCK_MINIPORTRETURNPACKETHANDLER,
    NDIS_MINIPORT_BLOCK_SYNCHRONOUSRETURNPACKETHANDLER,
    NDIS_MINIPORT_BLOCK_TOPNDIS5PACKETINDICATEHANDLER,
    __OFFSET_MINIPORT_MAX
};

static const char* offset_generic_names_w7[__OFFSET_GENERIC_MAX][2] =
{

    [NDIS_PROTOCOL_BLOCK_NAME]               = { "_NDIS_PROTOCOL_BLOCK", "Name"               },
    [NDIS_PROTOCOL_BLOCK_OPENQUEUE]          = { "_NDIS_PROTOCOL_BLOCK", "OpenQueue"          },
    [NDIS_PROTOCOL_BLOCK_NEXTPROTOCOL]       = { "_NDIS_PROTOCOL_BLOCK", "NextProtocol"       },
    [NDIS_OPEN_BLOCK_ROOTDEVICENAME]         = { "_NDIS_OPEN_BLOCK",     "RootDeviceName"     },
    [NDIS_OPEN_BLOCK_PROTOCOLNEXTOPEN]       = { "_NDIS_OPEN_BLOCK",     "ProtocolNextOpen"   },
    [NDIS_OPEN_BLOCK_MINIPORTHANDLE]         = { "_NDIS_OPEN_BLOCK",     "MiniportHandle"     },
    [NDIS_MINIPORT_BLOCK_MINIPORTNAME]       = { "_NDIS_MINIPORT_BLOCK", "MiniportName"       },
    [NDIS_MINIPORT_BLOCK_NEXTGLOBALMINIPORT] = { "_NDIS_MINIPORT_BLOCK", "NextGlobalMiniport" }
};

static const char* offset_generic_names_w10[__OFFSET_GENERIC_MAX][2] =
{

    [NDIS_PROTOCOL_BLOCK_NAME]               = { "_NDIS_PROTOCOL_BLOCK",    "Name"               },
    [NDIS_PROTOCOL_BLOCK_OPENQUEUE]          = { "_NDIS_PROTOCOL_BLOCK",    "OpenQueue"          },
    [NDIS_PROTOCOL_BLOCK_NEXTPROTOCOL]       = { "_NDIS_PROTOCOL_BLOCK",    "NextProtocol"       },
    [NDIS_OPEN_BLOCK_ROOTDEVICENAME]         = { "_NDIS_COMMON_OPEN_BLOCK", "RootDeviceName"     },
    [NDIS_OPEN_BLOCK_PROTOCOLNEXTOPEN]       = { "_NDIS_COMMON_OPEN_BLOCK", "ProtocolNextOpen"   },
    [NDIS_OPEN_BLOCK_MINIPORTHANDLE]         = { "_NDIS_COMMON_OPEN_BLOCK", "MiniportHandle"     },
    [NDIS_MINIPORT_BLOCK_MINIPORTNAME]       = { "_NDIS_MINIPORT_BLOCK",    "MiniportName"       },
    [NDIS_MINIPORT_BLOCK_NEXTGLOBALMINIPORT] = { "_NDIS_MINIPORT_BLOCK",    "NextGlobalMiniport" }
};

static const char* offset_open_names_w7[__OFFSET_OPEN_MAX][2] =
{
    [NDIS_OPEN_BLOCK_SENDHANDLER]                    = { "_NDIS_OPEN_BLOCK", "SendHandler"                    },
    [NDIS_OPEN_BLOCK_WANSENDHANDLER]                 = { "_NDIS_OPEN_BLOCK", "WanSendHandler"                 },
    [NDIS_OPEN_BLOCK_TRANSFERDATAHANDLER]            = { "_NDIS_OPEN_BLOCK", "TransferDataHandler"            },
    [NDIS_OPEN_BLOCK_SENDCOMPLETEHANDLER]            = { "_NDIS_OPEN_BLOCK", "SendCompleteHandler"            },
    [NDIS_OPEN_BLOCK_TRANSFERDATACOMPLETEHANDLER]    = { "_NDIS_OPEN_BLOCK", "TransferDataCompleteHandler"    },
    [NDIS_OPEN_BLOCK_RECEIVEHANDLER]                 = { "_NDIS_OPEN_BLOCK", "ReceiveHandler"                 },
    [NDIS_OPEN_BLOCK_RECEIVECOMPLETEHANDLER]         = { "_NDIS_OPEN_BLOCK", "ReceiveCompleteHandler"         },
    [NDIS_OPEN_BLOCK_WANRECEIVEHANDLER]              = { "_NDIS_OPEN_BLOCK", "WanReceiveHandler"              },
    [NDIS_OPEN_BLOCK_REQUESTCOMPLETEHANDLER]         = { "_NDIS_OPEN_BLOCK", "RequestCompleteHandler"         },
    [NDIS_OPEN_BLOCK_RECEIVEPACKETHANDLER]           = { "_NDIS_OPEN_BLOCK", "ReceivePacketHandler"           },
    [NDIS_OPEN_BLOCK_SENDPACKETSHANDLER]             = { "_NDIS_OPEN_BLOCK", "SendPacketsHandler"             },
    [NDIS_OPEN_BLOCK_RESETHANDLER]                   = { "_NDIS_OPEN_BLOCK", "ResetHandler"                   },
    [NDIS_OPEN_BLOCK_REQUESTHANDLER]                 = { "_NDIS_OPEN_BLOCK", "RequestHandler"                 },
    [NDIS_OPEN_BLOCK_OIDREQUESTHANDLER]              = { "_NDIS_OPEN_BLOCK", "OidRequestHandler"              },
    [NDIS_OPEN_BLOCK_RESETCOMPLETEHANDLER]           = { "_NDIS_OPEN_BLOCK", "ResetCompleteHandler"           },
    [NDIS_OPEN_BLOCK_STATUSHANDLER]                  = { "_NDIS_OPEN_BLOCK", "StatusHandler"                  },
    [NDIS_OPEN_BLOCK_STATUSHANDLEREX]                = { "_NDIS_OPEN_BLOCK", "StatusHandlerEx"                },
    [NDIS_OPEN_BLOCK_STATUSCOMPLETEHANDLER]          = { "_NDIS_OPEN_BLOCK", "StatusCompleteHandler"          },
    [NDIS_OPEN_BLOCK_PROTSENDNETBUFFERLISTSCOMPLETE] = { "_NDIS_OPEN_BLOCK", "ProtSendNetBufferListsComplete" },
    [NDIS_OPEN_BLOCK_RECEIVENETBUFFERLISTS]          = { "_NDIS_OPEN_BLOCK", "ReceiveNetBufferLists"          },
    [NDIS_OPEN_BLOCK_SAVEDSENDPACKETSHANDLER]        = { "_NDIS_OPEN_BLOCK", "SavedSendPacketsHandler"        },
    [NDIS_OPEN_BLOCK_SAVEDCANCELSENDPACKETSHANDLER]  = { "_NDIS_OPEN_BLOCK", "SavedCancelSendPacketsHandler"  },
    [NDIS_OPEN_BLOCK_SAVEDSENDHANDLER]               = { "_NDIS_OPEN_BLOCK", "SavedSendHandler"               }
};

static const char* offset_open_names_w10[__OFFSET_OPEN_MAX][2] =
{
    [NDIS_OPEN_BLOCK_SENDHANDLER]                    = { "_NDIS_COMMON_OPEN_BLOCK", "SendHandler"                    },
    [NDIS_OPEN_BLOCK_WANSENDHANDLER]                 = { "_NDIS_COMMON_OPEN_BLOCK", "WanSendHandler"                 },
    [NDIS_OPEN_BLOCK_TRANSFERDATAHANDLER]            = { "_NDIS_COMMON_OPEN_BLOCK", "TransferDataHandler"            },
    [NDIS_OPEN_BLOCK_SENDCOMPLETEHANDLER]            = { "_NDIS_COMMON_OPEN_BLOCK", "SendCompleteHandler"            },
    [NDIS_OPEN_BLOCK_TRANSFERDATACOMPLETEHANDLER]    = { "_NDIS_COMMON_OPEN_BLOCK", "TransferDataCompleteHandler"    },
    [NDIS_OPEN_BLOCK_RECEIVEHANDLER]                 = { "_NDIS_COMMON_OPEN_BLOCK", "ReceiveHandler"                 },
    [NDIS_OPEN_BLOCK_RECEIVECOMPLETEHANDLER]         = { "_NDIS_COMMON_OPEN_BLOCK", "ReceiveCompleteHandler"         },
    [NDIS_OPEN_BLOCK_WANRECEIVEHANDLER]              = { "_NDIS_COMMON_OPEN_BLOCK", "WanReceiveHandler"              },
    [NDIS_OPEN_BLOCK_REQUESTCOMPLETEHANDLER]         = { "_NDIS_COMMON_OPEN_BLOCK", "RequestCompleteHandler"         },
    [NDIS_OPEN_BLOCK_RECEIVEPACKETHANDLER]           = { "_NDIS_COMMON_OPEN_BLOCK", "ReceivePacketHandler"           },
    [NDIS_OPEN_BLOCK_SENDPACKETSHANDLER]             = { "_NDIS_COMMON_OPEN_BLOCK", "SendPacketsHandler"             },
    [NDIS_OPEN_BLOCK_RESETHANDLER]                   = { "_NDIS_COMMON_OPEN_BLOCK", "ResetHandler"                   },
    [NDIS_OPEN_BLOCK_REQUESTHANDLER]                 = { "_NDIS_COMMON_OPEN_BLOCK", "RequestHandler"                 },
    [NDIS_OPEN_BLOCK_OIDREQUESTHANDLER]              = { "_NDIS_COMMON_OPEN_BLOCK", "OidRequestHandler"              },
    [NDIS_OPEN_BLOCK_RESETCOMPLETEHANDLER]           = { "_NDIS_COMMON_OPEN_BLOCK", "ResetCompleteHandler"           },
    [NDIS_OPEN_BLOCK_STATUSHANDLER]                  = { "_NDIS_COMMON_OPEN_BLOCK", "StatusHandler"                  },
    [NDIS_OPEN_BLOCK_STATUSHANDLEREX]                = { "_NDIS_COMMON_OPEN_BLOCK", "StatusHandlerEx"                },
    [NDIS_OPEN_BLOCK_STATUSCOMPLETEHANDLER]          = { "_NDIS_COMMON_OPEN_BLOCK", "StatusCompleteHandler"          },
    [NDIS_OPEN_BLOCK_PROTSENDNETBUFFERLISTSCOMPLETE] = { "_NDIS_COMMON_OPEN_BLOCK", "ProtSendNetBufferListsComplete" },
    [NDIS_OPEN_BLOCK_RECEIVENETBUFFERLISTS]          = { "_NDIS_COMMON_OPEN_BLOCK", "ReceiveNetBufferLists"          },
    [NDIS_OPEN_BLOCK_SAVEDSENDPACKETSHANDLER]        = { "_NDIS_COMMON_OPEN_BLOCK", "SavedSendPacketsHandler"        },
    [NDIS_OPEN_BLOCK_SAVEDCANCELSENDPACKETSHANDLER]  = { "_NDIS_COMMON_OPEN_BLOCK", "SavedCancelSendPacketsHandler"  },
    [NDIS_OPEN_BLOCK_SAVEDSENDHANDLER]               = { "_NDIS_COMMON_OPEN_BLOCK", "SavedSendHandler"               }
};

static const char* offset_miniport_names[__OFFSET_MINIPORT_MAX][2] = 
{
    [NDIS_MINIPORT_BLOCK_NEXTCANCELSENDNETBUFFERLISTSHANDLER]      = { "_NDIS_MINIPORT_BLOCK", "NextCancelSendNetBufferListsHandler"      },
    [NDIS_MINIPORT_BLOCK_PACKETINDICATEHANDLER]                    = { "_NDIS_MINIPORT_BLOCK", "PacketIndicateHandler"                    },
    [NDIS_MINIPORT_BLOCK_SENDCOMPLETEHANDLER]                      = { "_NDIS_MINIPORT_BLOCK", "SendCompleteHandler"                      },
    [NDIS_MINIPORT_BLOCK_SENDRESOURCESHANDLER]                     = { "_NDIS_MINIPORT_BLOCK", "SendResourcesHandler"                     },
    [NDIS_MINIPORT_BLOCK_RESETCOMPLETEHANDLER]                     = { "_NDIS_MINIPORT_BLOCK", "ResetCompleteHandler"                     },
    [NDIS_MINIPORT_BLOCK_DISABLEINTERRUPTHANDLER]                  = { "_NDIS_MINIPORT_BLOCK", "DisableInterruptHandler"                  },
    [NDIS_MINIPORT_BLOCK_ENABLEINTERRUPTHANDLER]                   = { "_NDIS_MINIPORT_BLOCK", "EnableInterruptHandler"                   },
    [NDIS_MINIPORT_BLOCK_SENDPACKETSHANDLER]                       = { "_NDIS_MINIPORT_BLOCK", "SendPacketsHandler"                       },
    [NDIS_MINIPORT_BLOCK_DEFERREDSENDHANDLER]                      = { "_NDIS_MINIPORT_BLOCK", "DeferredSendHandler"                      },
    [NDIS_MINIPORT_BLOCK_ETHRXINDICATEHANDLER]                     = { "_NDIS_MINIPORT_BLOCK", "EthRxIndicateHandler"                     },
    [NDIS_MINIPORT_BLOCK_NEXTSENDNETBUFFERLISTSHANDLER]            = { "_NDIS_MINIPORT_BLOCK", "NextSendNetBufferListsHandler"            },
    [NDIS_MINIPORT_BLOCK_ETHRXCOMPLETEHANDLER]                     = { "_NDIS_MINIPORT_BLOCK", "EthRxCompleteHandler"                     },
    [NDIS_MINIPORT_BLOCK_SAVEDNEXTSENDNETBUFFERLISTSHANDLER]       = { "_NDIS_MINIPORT_BLOCK", "SavedNextSendNetBufferListsHandler"       },
    [NDIS_MINIPORT_BLOCK_STATUSHANDLER]                            = { "_NDIS_MINIPORT_BLOCK", "StatusHandler"                            },
    [NDIS_MINIPORT_BLOCK_STATUSCOMPLETEHANDLER]                    = { "_NDIS_MINIPORT_BLOCK", "StatusCompleteHandler"                    },
    [NDIS_MINIPORT_BLOCK_TDCOMPLETEHANDLER]                        = { "_NDIS_MINIPORT_BLOCK", "TDCompleteHandler"                        },
    [NDIS_MINIPORT_BLOCK_QUERYCOMPLETEHANDLER]                     = { "_NDIS_MINIPORT_BLOCK", "QueryCompleteHandler"                     },
    [NDIS_MINIPORT_BLOCK_SETCOMPLETEHANDLER]                       = { "_NDIS_MINIPORT_BLOCK", "SetCompleteHandler"                       },
    [NDIS_MINIPORT_BLOCK_WANSENDCOMPLETEHANDLER]                   = { "_NDIS_MINIPORT_BLOCK", "WanSendCompleteHandler"                   },
    [NDIS_MINIPORT_BLOCK_WANRCVHANDLER]                            = { "_NDIS_MINIPORT_BLOCK", "WanRcvHandler"                            },
    [NDIS_MINIPORT_BLOCK_WANRCVCOMPLETEHANDLER]                    = { "_NDIS_MINIPORT_BLOCK", "WanRcvCompleteHandler"                    },
    [NDIS_MINIPORT_BLOCK_SENDNETBUFFERLISTSCOMPLETEHANDLER]        = { "_NDIS_MINIPORT_BLOCK", "SendNetBufferListsCompleteHandler"        },
    [NDIS_MINIPORT_BLOCK_SAVEDPACKETINDICATEHANDLER]               = { "_NDIS_MINIPORT_BLOCK", "SavedPacketIndicateHandler"               },
    [NDIS_MINIPORT_BLOCK_NEXTSENDPACKETSHANDLER]                   = { "_NDIS_MINIPORT_BLOCK", "NextSendPacketsHandler"                   },
    [NDIS_MINIPORT_BLOCK_FINALSENDPACKETSHANDLER]                  = { "_NDIS_MINIPORT_BLOCK", "FinalSendPacketsHandler"                  },
    [NDIS_MINIPORT_BLOCK_SHUTDOWNHANDLER]                          = { "_NDIS_MINIPORT_BLOCK", "ShutdownHandler"                          },
    [NDIS_MINIPORT_BLOCK_TOPINDICATENETBUFFERLISTSHANDLER]         = { "_NDIS_MINIPORT_BLOCK", "TopIndicateNetBufferListsHandler"         },
    [NDIS_MINIPORT_BLOCK_TOPINDICATELOOPBACKNETBUFFERLISTSHANDLER] = { "_NDIS_MINIPORT_BLOCK", "TopIndicateLoopbackNetBufferListsHandler" },
    [NDIS_MINIPORT_BLOCK_NDIS5PACKETINDICATEHANDLER]               = { "_NDIS_MINIPORT_BLOCK", "Ndis5PacketIndicateHandler"               },
    [NDIS_MINIPORT_BLOCK_MINIPORTRETURNPACKETHANDLER]              = { "_NDIS_MINIPORT_BLOCK", "MiniportReturnPacketHandler"              },
    [NDIS_MINIPORT_BLOCK_SYNCHRONOUSRETURNPACKETHANDLER]           = { "_NDIS_MINIPORT_BLOCK", "SynchronousReturnPacketHandler"           },
    [NDIS_MINIPORT_BLOCK_TOPNDIS5PACKETINDICATEHANDLER]            = { "_NDIS_MINIPORT_BLOCK", "TopNdis5PacketIndicateHandler"            }
};