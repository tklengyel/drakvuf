/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

#ifndef LIBFS_EXT4_PRIVATE
#define LIBFS_EXT4_PRIVATE

#include <stdint.h>

#include <cstring>
#include <map>
#include <memory>
#include <cassert>

namespace libfs
{

#define GROUP_0_PADDING 1024

#define EXT4_MAGIC 0xEF53

#define EXT4_LABEL_MAX 16

#define    EXT4_NDIR_BLOCKS        12
#define    EXT4_IND_BLOCK          EXT4_NDIR_BLOCKS
#define    EXT4_DIND_BLOCK         (EXT4_IND_BLOCK + 1)
#define    EXT4_TIND_BLOCK         (EXT4_DIND_BLOCK + 1)
#define    EXT4_N_BLOCKS           (EXT4_TIND_BLOCK + 1)
#define    EXT4_I_DATA_SIZE        EXT4_N_BLOCKS << 2

/*
 * Codes for operating systems
 */
#define EXT4_OS_LINUX       0
#define EXT4_OS_HURD        1
#define EXT4_OS_MASIX       2
#define EXT4_OS_FREEBSD     3
#define EXT4_OS_LITES       4

/*
 * Feature set definitions
 */

enum
{
    EXT4_FEATURE_COMPAT_DIR_PREALLOC    = 0x0001,
    EXT4_FEATURE_COMPAT_IMAGIC_INODES   = 0x0002,
    EXT4_FEATURE_COMPAT_HAS_JOURNAL     = 0x0004,
    EXT4_FEATURE_COMPAT_EXT_ATTR        = 0x0008,
    EXT4_FEATURE_COMPAT_RESIZE_INODE    = 0x0010,
    EXT4_FEATURE_COMPAT_DIR_INDEX       = 0x0020,
    EXT4_FEATURE_COMPAT_SPARSE_SUPER2   = 0x0200,
};

static inline std::map<uint64_t, std::string> ext4_feature_compat =
{
    { EXT4_FEATURE_COMPAT_DIR_PREALLOC,  "dir_prealloc"  },
    { EXT4_FEATURE_COMPAT_IMAGIC_INODES, "imagic_inodes" },
    { EXT4_FEATURE_COMPAT_HAS_JOURNAL,   "has_journal"   },
    { EXT4_FEATURE_COMPAT_EXT_ATTR,      "ext_attr"      },
    { EXT4_FEATURE_COMPAT_RESIZE_INODE,  "resize_inode"  },
    { EXT4_FEATURE_COMPAT_DIR_INDEX,     "dir_index"     },
    { EXT4_FEATURE_COMPAT_SPARSE_SUPER2, "sparse_super2" },
};

enum
{
    EXT4_FEATURE_INCOMPAT_COMPRESSION = 0x0001,
    EXT4_FEATURE_INCOMPAT_FILETYPE    = 0x0002,
    EXT4_FEATURE_INCOMPAT_RECOVER     = 0x0004, /* Needs recovery */
    EXT4_FEATURE_INCOMPAT_JOURNAL_DEV = 0x0008, /* Journal device */
    EXT4_FEATURE_INCOMPAT_META_BG     = 0x0010,
    EXT4_FEATURE_INCOMPAT_EXTENTS     = 0x0040, /* extents support */
    EXT4_FEATURE_INCOMPAT_64BIT       = 0x0080,
    EXT4_FEATURE_INCOMPAT_MMP         = 0x0100,
    EXT4_FEATURE_INCOMPAT_FLEX_BG     = 0x0200,
    EXT4_FEATURE_INCOMPAT_EA_INODE    = 0x0400, /* EA in inode */
    EXT4_FEATURE_INCOMPAT_DIRDATA     = 0x1000, /* data in dirent */
    EXT4_FEATURE_INCOMPAT_CSUM_SEED   = 0x2000,
    EXT4_FEATURE_INCOMPAT_LARGEDIR    = 0x4000, /* >2GB or 3-lvl htree */
    EXT4_FEATURE_INCOMPAT_INLINE_DATA = 0x8000, /* data in inode */
    EXT4_FEATURE_INCOMPAT_ENCRYPT     = 0x10000,
    EXT4_FEATURE_INCOMPAT_CASEFOLD    = 0x20000,
};

static inline std::map<uint64_t, std::string> ext4_feature_incompat =
{
    { EXT4_FEATURE_INCOMPAT_COMPRESSION, "compression" },
    { EXT4_FEATURE_INCOMPAT_FILETYPE,    "filetype"    },
    { EXT4_FEATURE_INCOMPAT_RECOVER,     "recover"     },
    { EXT4_FEATURE_INCOMPAT_JOURNAL_DEV, "journal_dev" },
    { EXT4_FEATURE_INCOMPAT_META_BG,     "meta_bg"     },
    { EXT4_FEATURE_INCOMPAT_EXTENTS,     "extents"     },
    { EXT4_FEATURE_INCOMPAT_64BIT,       "64bit"       },
    { EXT4_FEATURE_INCOMPAT_MMP,         "mmp"         },
    { EXT4_FEATURE_INCOMPAT_FLEX_BG,     "flex_bg"     },
    { EXT4_FEATURE_INCOMPAT_EA_INODE,    "ea_inode"    },
    { EXT4_FEATURE_INCOMPAT_DIRDATA,     "dirdata"     },
    { EXT4_FEATURE_INCOMPAT_CSUM_SEED,   "csum_seed"   },
    { EXT4_FEATURE_INCOMPAT_LARGEDIR,    "largedir"    },
    { EXT4_FEATURE_INCOMPAT_INLINE_DATA, "inline_data" },
    { EXT4_FEATURE_INCOMPAT_ENCRYPT,     "encrypt"     },
    { EXT4_FEATURE_INCOMPAT_CASEFOLD,    "casefold"    },
};

/*
 * Structure of the super block
 * https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#Overview
 * https://elixir.bootlin.com/linux/latest/source/fs/ext4/ext4.h#L1319
 */
#pragma pack(push, 1)
struct ext4_super_block
{
    /*00*/    uint32_t    s_inodes_count;        /* Inodes count */
    uint32_t    s_blocks_count_lo;    /* Blocks count */
    uint32_t    s_r_blocks_count_lo;    /* Reserved blocks count */
    uint32_t    s_free_blocks_count_lo;    /* Free blocks count */
    /*10*/    uint32_t    s_free_inodes_count;    /* Free inodes count */
    uint32_t    s_first_data_block;    /* First Data Block */
    uint32_t    s_log_block_size;    /* Block size */
    uint32_t    s_log_cluster_size;    /* Allocation cluster size */
    /*20*/    uint32_t    s_blocks_per_group;    /* # Blocks per group */
    uint32_t    s_clusters_per_group;    /* # Clusters per group */
    uint32_t    s_inodes_per_group;    /* # Inodes per group */
    uint32_t    s_mtime;        /* Mount time */
    /*30*/    uint32_t    s_wtime;        /* Write time */
    uint16_t    s_mnt_count;        /* Mount count */
    uint16_t    s_max_mnt_count;    /* Maximal mount count */
    uint16_t    s_magic;        /* Magic signature */
    uint16_t    s_state;        /* File system state */
    uint16_t    s_errors;        /* Behaviour when detecting errors */
    uint16_t    s_minor_rev_level;    /* minor revision level */
    /*40*/    uint32_t    s_lastcheck;        /* time of last check */
    uint32_t    s_checkinterval;    /* max. time between checks */
    uint32_t    s_creator_os;        /* OS */
    uint32_t    s_rev_level;        /* Revision level */
    /*50*/    uint16_t    s_def_resuid;        /* Default uid for reserved blocks */
    uint16_t    s_def_resgid;        /* Default gid for reserved blocks */
    /*
    * These fields are for EXT4_DYNAMIC_REV superblocks only.
    *
    * Note: the difference between the compatible feature set and
    * the incompatible feature set is that if there is a bit set
    * in the incompatible feature set that the kernel doesn't
    * know about, it should refuse to mount the filesystem.
    *
    * e2fsck's requirements are more strict; if it doesn't know
    * about a feature in either the compatible or incompatible
    * feature set, it must abort and not try to meddle with
    * things it doesn't understand...
    */
    uint32_t    s_first_ino;        /* First non-reserved inode */
    uint16_t    s_inode_size;        /* size of inode structure */
    uint16_t    s_block_group_nr;    /* block group # of this superblock */
    uint32_t    s_feature_compat;    /* compatible feature set */
    /*60*/    uint32_t    s_feature_incompat;    /* incompatible feature set */
    uint32_t    s_feature_ro_compat;/* readonly-compatible feature set */
    /*68*/    uint8_t        s_uuid[16];            /* 128-bit uuid for volume */
    /*78*/    char        s_volume_name[EXT4_LABEL_MAX];    /* volume name */
    /*88*/    char        s_last_mounted[64];    /* directory where last mounted */
    /*C8*/    uint32_t    s_algorithm_usage_bitmap; /* For compression */
    /*
    * Performance hints.  Directory preallocation should only
    * happen if the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
    */
    uint8_t        s_prealloc_blocks;    /* Nr of blocks to try to preallocate*/
    uint8_t        s_prealloc_dir_blocks;    /* Nr to preallocate for dirs */
    uint16_t    s_reserved_gdt_blocks;    /* Per group desc for online growth */
    /*
    * Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set.
    */
    /*D0*/    uint8_t        s_journal_uuid[16];    /* uuid of journal superblock */
    /*E0*/    uint32_t    s_journal_inum;        /* inode number of journal file */
    uint32_t    s_journal_dev;        /* device number of journal file */
    uint32_t    s_last_orphan;        /* start of list of inodes to delete */
    uint32_t    s_hash_seed[4];        /* HTREE hash seed */
    uint8_t     s_def_hash_version;    /* Default hash version to use */
    uint8_t     s_jnl_backup_type;
    uint16_t    s_desc_size;        /* size of group descriptor */
    /*100*/    uint32_t    s_default_mount_opts;
    uint32_t    s_first_meta_bg;    /* First metablock block group */
    uint32_t    s_mkfs_time;        /* When the filesystem was created */
    uint32_t    s_jnl_blocks[17];    /* Backup of the journal inode */
    /* 64bit support valid if EXT4_FEATURE_INCOMPAT_64BIT */
    /*150*/    uint32_t    s_blocks_count_hi;    /* Blocks count */
    uint32_t    s_r_blocks_count_hi;    /* Reserved blocks count */
    uint32_t    s_free_blocks_count_hi;    /* Free blocks count */
    uint16_t    s_min_extra_isize;    /* All inodes have at least # bytes */
    uint16_t    s_want_extra_isize;     /* New inodes should reserve # bytes */
    uint32_t    s_flags;        /* Miscellaneous flags */
    uint16_t    s_raid_stride;        /* RAID stride */
    uint16_t    s_mmp_update_interval;  /* # seconds to wait in MMP checking */
    uint64_t    s_mmp_block;            /* Block for multi-mount protection */
    uint32_t    s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
    uint8_t     s_log_groups_per_flex;  /* FLEX_BG group size */
    uint8_t     s_checksum_type;    /* metadata checksum algorithm used */
    uint8_t     s_encryption_level;    /* versioning level for encryption */
    uint8_t     s_reserved_pad;        /* Padding to next 32bits */
    uint64_t    s_kbytes_written;    /* nr of lifetime kilobytes written */
    uint32_t    s_snapshot_inum;    /* Inode number of active snapshot */
    uint32_t    s_snapshot_id;        /* sequential ID of active snapshot */
    uint64_t    s_snapshot_r_blocks_count; /* reserved blocks for active snapshot's future use */
    uint32_t    s_snapshot_list;    /* inode number of the head of the on-disk snapshot list */
#define EXT4_S_ERR_START offsetof(struct ext4_super_block, s_error_count)
    uint32_t    s_error_count;        /* number of fs errors */
    uint32_t    s_first_error_time;    /* first time an error happened */
    uint32_t    s_first_error_ino;    /* inode involved in first error */
    uint64_t    s_first_error_block;    /* block involved of first error */
    uint8_t     s_first_error_func[32];    /* function where the error happened */
    uint32_t    s_first_error_line;    /* line number where error happened */
    uint32_t    s_last_error_time;    /* most recent time of an error */
    uint32_t    s_last_error_ino;    /* inode involved in last error */
    uint32_t    s_last_error_line;    /* line number where error happened */
    uint64_t    s_last_error_block;    /* block involved of last error */
    uint8_t     s_last_error_func[32];    /* function where the error happened */
#define EXT4_S_ERR_END offsetof(struct ext4_super_block, s_mount_opts)
    uint8_t     s_mount_opts[64];
    uint32_t    s_usr_quota_inum;    /* inode for tracking user quota */
    uint32_t    s_grp_quota_inum;    /* inode for tracking group quota */
    uint32_t    s_overhead_clusters;    /* overhead blocks/clusters in fs */
    uint32_t    s_backup_bgs[2];    /* groups with sparse_super2 SBs */
    uint8_t     s_encrypt_algos[4];    /* Encryption algorithms in use  */
    uint8_t     s_encrypt_pw_salt[16];    /* Salt used for string2key algorithm */
    uint32_t    s_lpf_ino;        /* Location of the lost+found inode */
    uint32_t    s_prj_quota_inum;    /* inode for tracking project quota */
    uint32_t    s_checksum_seed;    /* crc32c(uuid) if csum_seed set */
    uint8_t     s_wtime_hi;
    uint8_t     s_mtime_hi;
    uint8_t     s_mkfs_time_hi;
    uint8_t     s_lastcheck_hi;
    uint8_t     s_first_error_time_hi;
    uint8_t     s_last_error_time_hi;
    uint8_t     s_first_error_errcode;
    uint8_t     s_last_error_errcode;
    uint16_t    s_encoding;        /* Filename charset encoding */
    uint16_t    s_encoding_flags;    /* Filename charset encoding flags */
    uint32_t    s_orphan_file_inum;    /* Inode for tracking orphan inodes */
    uint32_t    s_reserved[94];        /* Padding to the end of the block */
    uint32_t    s_checksum;        /* crc32c(superblock) */

    uint64_t get_block_count()
    {
        return (uint64_t)s_blocks_count_lo + ((uint64_t)s_blocks_count_hi << 32);
    }

    uint64_t get_reservered_block_count()
    {
        return (uint64_t)s_r_blocks_count_lo + ((uint64_t)s_r_blocks_count_hi << 32);
    }

    uint64_t get_free_block_count()
    {
        return (uint64_t)s_free_blocks_count_lo + ((uint64_t)s_free_blocks_count_hi << 32);
    }

    uint32_t get_block_size()
    {
        return 1 << (10 + s_log_block_size);
    };

    uint64_t get_groups_per_flex()
    {
        return 1 << s_log_groups_per_flex;
    }

    std::string get_features_compat()
    {
        std::string output;

        for (const auto& flag: ext4_feature_compat)
        {
            if ((flag.first & s_feature_compat) == flag.first)
            {
                output += flag.second + " ";
            }
        }
        output.resize(output.size() - 1);
        return output;
    }

    std::string get_features_incompat()
    {
        std::string output;

        for (const auto& flag: ext4_feature_incompat)
        {
            if ((flag.first & s_feature_incompat) == flag.first)
            {
                output += flag.second + " ";
            }
        }
        output.resize(output.size() - 1);
        return output;
    }
};
#pragma pack(pop)
typedef struct ext4_super_block* ext4_super_block_t;

/*
 * Extent tree
 */
#define EXT4_EXTENT_HEADER_MAGIC 0xF30A

#pragma pack(push, 1)
struct ext4_extent_header
{
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
};
#pragma pack(pop)
typedef ext4_extent_header* ext4_extent_header_t;

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
#pragma pack(push, 1)
struct ext4_extent_idx
{
    uint32_t    ei_block;    /* index covers logical blocks from 'block' */
    uint32_t    ei_leaf_lo;    /* pointer to the physical block of the next level. leaf or next index could be there */
    uint16_t    ei_leaf_hi;    /* high 16 bits of physical block */
    uint16_t    ei_unused;

    uint64_t get_leaf()
    {
        return ((uint64_t)ei_leaf_hi << 32) | (uint64_t)ei_leaf_lo;
    }
};
#pragma pack(pop)
typedef ext4_extent_idx* ext4_extent_idx_t;

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
#define EXT_INIT_MAX_LEN (1UL << 15)
#pragma pack(push, 1)
struct ext4_extent
{
    uint32_t    ee_block;       /* first logical block extent covers */
    uint16_t    ee_len;         /* number of blocks covered by extent */
    uint16_t    ee_start_hi;    /* high 16 bits of physical block */
    uint32_t    ee_start_lo;    /* low 32 bits of physical block */

    uint64_t get_start()
    {
        return ((uint64_t)ee_start_hi << 32) | (uint64_t)ee_start_lo;
    }
};
#pragma pack(pop)
typedef ext4_extent* ext4_extent_t;

typedef union
{
    ext4_extent extent;
    ext4_extent_idx extent_idx;
} ext4_extent_union;

/*
 * This is the extent tail on-disk structure.
 * All other extent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid ext4 block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct ext4_extent_tail
{
    uint32_t    et_checksum;    /* crc32c(uuid+inum+extent_block) */
};

/*
 * Structure of a blocks group descriptor
 */
#pragma pack(push, 1)
struct ext4_group_desc
{
    uint32_t    bg_block_bitmap_lo;    /* Blocks bitmap block */
    uint32_t    bg_inode_bitmap_lo;    /* Inodes bitmap block */
    uint32_t    bg_inode_table_lo;    /* Inodes table block */
    uint16_t    bg_free_blocks_count_lo;/* Free blocks count */
    uint16_t    bg_free_inodes_count_lo;/* Free inodes count */
    uint16_t    bg_used_dirs_count_lo;    /* Directories count */
    uint16_t    bg_flags;        /* EXT4_BG_flags (INODE_UNINIT, etc) */
    uint32_t    bg_exclude_bitmap_lo;   /* Exclude bitmap for snapshots */
    uint16_t    bg_block_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+bbitmap) LE */
    uint16_t    bg_inode_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+ibitmap) LE */
    uint16_t    bg_itable_unused_lo;    /* Unused inodes count */
    uint16_t    bg_checksum;        /* crc16(sb_uuid+group+desc) */
    uint32_t    bg_block_bitmap_hi;    /* Blocks bitmap block MSB */
    uint32_t    bg_inode_bitmap_hi;    /* Inodes bitmap block MSB */
    uint32_t    bg_inode_table_hi;    /* Inodes table block MSB */
    uint16_t    bg_free_blocks_count_hi;/* Free blocks count MSB */
    uint16_t    bg_free_inodes_count_hi;/* Free inodes count MSB */
    uint16_t    bg_used_dirs_count_hi;    /* Directories count MSB */
    uint16_t    bg_itable_unused_hi;    /* Unused inodes count MSB */
    uint32_t    bg_exclude_bitmap_hi;   /* Exclude bitmap block MSB */
    uint16_t    bg_block_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+bbitmap) BE */
    uint16_t    bg_inode_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+ibitmap) BE */
    uint32_t    bg_reserved;

    uint64_t get_inode_table()
    {
        return (uint64_t)(bg_inode_table_lo) | ((uint64_t)bg_inode_table_hi << 32);
    };
};
#pragma pack(pop)
typedef struct ext4_group_desc* ext4_group_desc_t;

enum ext4_inode_i_mode
{
    EXT4_S_IXOTH  = 0x1,     /* (Others may execute) */
    EXT4_S_IWOTH  = 0x2,     /* (Others may write) */
    EXT4_S_IROTH  = 0x4,     /* (Others may read) */
    EXT4_S_IXGRP  = 0x8,     /* (Group members may execute) */
    EXT4_S_IWGRP  = 0x10,    /* (Group members may write) */
    EXT4_S_IRGRP  = 0x20,    /* (Group members may read) */
    EXT4_S_IXUSR  = 0x40,    /* (Owner may execute) */
    EXT4_S_IWUSR  = 0x80,    /* (Owner may write) */
    EXT4_S_IRUSR  = 0x100,   /* (Owner may read) */
    EXT4_S_ISVTX  = 0x200,   /* (Sticky bit) */
    EXT4_S_ISGID  = 0x400,   /* (Set GID) */
    EXT4_S_ISUID  = 0x800,   /* (Set UID) */
    // These are mutually-exclusive file types:
    EXT4_S_IFIFO  = 0x1000,  /* (FIFO) */
    EXT4_S_IFCHR  = 0x2000,  /* (Character device) */
    EXT4_S_IFDIR  = 0x4000,  /* (Directory) */
    EXT4_S_IFBLK  = 0x6000,  /* (Block device) */
    EXT4_S_IFREG  = 0x8000,  /* (Regular file) */
    EXT4_S_IFLNK  = 0xA000,  /* (Symbolic link) */
    EXT4_S_IFSOCK = 0xC000,  /* (Socket)  */
};

enum ext4_inode_i_flags
{
    EXT4_SECRM_FL            = 0x1, /* This file requires secure deletion (EXT4_SECRM_FL). (not implemented) */
    EXT4_UNRM_FL             = 0x2, /* This file should be preserved, should undeletion be desired (EXT4_UNRM_FL). (not implemented) */
    EXT4_COMPR_FL            = 0x4, /* File is compressed (EXT4_COMPR_FL). (not really implemented) */
    EXT4_SYNC_FL             = 0x8, /* All writes to the file must be synchronous (EXT4_SYNC_FL). */
    EXT4_IMMUTABLE_FL        = 0x10, /* File is immutable (EXT4_IMMUTABLE_FL). */
    EXT4_APPEND_FL           = 0x20, /* File can only be appended (EXT4_APPEND_FL). */
    EXT4_NODUMP_FL           = 0x40, /* The dump(1) utility should not dump this file (EXT4_NODUMP_FL). */
    EXT4_NOATIME_FL          = 0x80, /* Do not update access time (EXT4_NOATIME_FL). */
    EXT4_DIRTY_FL            = 0x100, /* Dirty compressed file (EXT4_DIRTY_FL). (not used) */
    EXT4_COMPRBLK_FL         = 0x200, /* File has one or more compressed clusters (EXT4_COMPRBLK_FL). (not used) */
    EXT4_NOCOMPR_FL          = 0x400, /* Do not compress file (EXT4_NOCOMPR_FL). (not used) */
    EXT4_ENCRYPT_FL          = 0x800, /* Encrypted inode (EXT4_ENCRYPT_FL). This bit value previously was EXT4_ECOMPR_FL (compression error), which was never used. */
    EXT4_INDEX_FL            = 0x1000, /* Directory has hashed indexes (EXT4_INDEX_FL). */
    EXT4_IMAGIC_FL           = 0x2000, /* AFS magic directory (EXT4_IMAGIC_FL). */
    EXT4_JOURNAL_DATA_FL     = 0x4000, /* File data must always be written through the journal (EXT4_JOURNAL_DATA_FL). */
    EXT4_NOTAIL_FL           = 0x8000, /* File tail should not be merged (EXT4_NOTAIL_FL). (not used by ext4) */
    EXT4_DIRSYNC_FL          = 0x10000, /* All directory entry data should be written synchronously (see dirsync) (EXT4_DIRSYNC_FL). */
    EXT4_TOPDIR_FL           = 0x20000, /* Top of directory hierarchy (EXT4_TOPDIR_FL). */
    EXT4_HUGE_FILE_FL        = 0x40000, /* This is a huge file (EXT4_HUGE_FILE_FL). */
    EXT4_EXTENTS_FL          = 0x80000, /* Inode uses extents (EXT4_EXTENTS_FL). */
    EXT4_EA_INODE_FL         = 0x200000, /* Inode stores a large extended attribute value in its data blocks (EXT4_EA_INODE_FL). */
    EXT4_EOFBLOCKS_FL        = 0x400000, /* This file has blocks allocated past EOF (EXT4_EOFBLOCKS_FL). (deprecated) */
    EXT4_SNAPFILE_FL         = 0x01000000, /* Inode is a snapshot (EXT4_SNAPFILE_FL). (not in mainline) */
    EXT4_SNAPFILE_DELETED_FL = 0x04000000, /* Snapshot is being deleted (EXT4_SNAPFILE_DELETED_FL). (not in mainline) */
    EXT4_SNAPFILE_SHRUNK_FL  = 0x08000000, /* Snapshot shrink has completed (EXT4_SNAPFILE_SHRUNK_FL). (not in mainline) */
    EXT4_INLINE_DATA_FL      = 0x10000000, /* Inode has inline data (EXT4_INLINE_DATA_FL). */
    EXT4_PROJINHERIT_FL      = 0x20000000, /* Create children with the same project ID (EXT4_PROJINHERIT_FL). */
    EXT4_RESERVED_FL         = 0x80000000, /* Reserved for ext4 library (EXT4_RESERVED_FL). */
};

/*
 * Structure of an inode on the disk
 */
#pragma pack(push, 1)
struct ext4_inode
{
    uint16_t    i_mode;        /* File mode */
    uint16_t    i_uid;        /* Low 16 bits of Owner Uid */
    uint32_t    i_size_lo;    /* Size in bytes */
    uint32_t    i_atime;    /* Access time */
    uint32_t    i_ctime;    /* Inode Change time */
    uint32_t    i_mtime;    /* Modification time */
    uint32_t    i_dtime;    /* Deletion Time */
    uint16_t    i_gid;        /* Low 16 bits of Group Id */
    uint16_t    i_links_count;    /* Links count */
    uint32_t    i_blocks_lo;    /* Blocks count */
    uint32_t    i_flags;    /* File flags */
    union
    {
        struct
        {
            uint32_t  l_i_version;
        } linux1;
        struct
        {
            uint32_t  h_i_translator;
        } hurd1;
        struct
        {
            uint32_t  m_i_reserved1;
        } masix1;
    } osd1;                /* OS dependent 1 */
    uint8_t     i_block[EXT4_I_DATA_SIZE]; /* Pointers to blocks, converted from uint32_t i_block[4] */
    uint32_t    i_generation;    /* File version (for NFS) */
    uint32_t    i_file_acl_lo;    /* File ACL */
    uint32_t    i_size_high;
    uint32_t    i_obso_faddr;    /* Obsoleted fragment address */
    union
    {
        struct
        {
            uint16_t    l_i_blocks_high; /* were l_i_reserved1 */
            uint16_t    l_i_file_acl_high;
            uint16_t    l_i_uid_high;    /* these 2 fields */
            uint16_t    l_i_gid_high;    /* were reserved2[0] */
            uint16_t    l_i_checksum_lo;/* crc32c(uuid+inum+inode) LE */
            uint16_t    l_i_reserved;
        } linux2;
        struct
        {
            uint16_t    h_i_reserved1;    /* Obsoleted fragment number/size which are removed in ext4 */
            uint16_t    h_i_mode_high;
            uint16_t    h_i_uid_high;
            uint16_t    h_i_gid_high;
            uint32_t    h_i_author;
        } hurd2;
        struct
        {
            uint16_t    h_i_reserved1;    /* Obsoleted fragment number/size which are removed in ext4 */
            uint16_t    m_i_file_acl_high;
            uint32_t    m_i_reserved2[2];
        } masix2;
    } osd2;                /* OS dependent 2 */
    uint16_t    i_extra_isize;
    uint16_t    i_checksum_hi;    /* crc32c(uuid+inum+inode) BE */
    uint32_t    i_ctime_extra;  /* extra Change time      (nsec << 2 | epoch) */
    uint32_t    i_mtime_extra;  /* extra Modification time(nsec << 2 | epoch) */
    uint32_t    i_atime_extra;  /* extra Access time      (nsec << 2 | epoch) */
    uint32_t    i_crtime;       /* File Creation time */
    uint32_t    i_crtime_extra; /* extra FileCreationtime (nsec << 2 | epoch) */
    uint32_t    i_version_hi;    /* high 32 bits for 64-bit version */
    uint32_t    i_projid;    /* Project ID */

    uint32_t get_uid()
    {
        return ((uint32_t)osd2.linux2.l_i_uid_high << 16) | i_uid;
    }

    uint32_t get_gid()
    {
        return ((uint32_t)osd2.linux2.l_i_gid_high << 16) | i_gid;
    }

    uint64_t get_inode_size()
    {
        return (uint64_t)i_size_lo | ((uint64_t)i_size_high << 32);
    }

    uint64_t get_blocks_count()
    {
        return (uint64_t)i_blocks_lo | ((uint64_t)osd2.linux2.l_i_blocks_high << 32);
    }

    ext4_inode_i_mode get_filetype()
    {
        return static_cast<ext4_inode_i_mode>(i_mode & 0xF000);
    }

    std::unique_ptr<ext4_extent_header> get_extent_header()
    {
        auto header = std::make_unique<ext4_extent_header>(*reinterpret_cast<ext4_extent_header_t>(i_block));;
        assert(header->eh_magic == EXT4_EXTENT_HEADER_MAGIC);
        return header;
    }

    std::unique_ptr<ext4_extent> get_extent(uint64_t index)
    {
        return std::make_unique<ext4_extent>(*reinterpret_cast<ext4_extent_t>(
                    i_block + sizeof(ext4_extent_header) * (index + 1)
                ));
    }

    std::unique_ptr<ext4_extent_idx> get_extent_idx(uint64_t index)
    {
        return std::make_unique<ext4_extent_idx>(*reinterpret_cast<ext4_extent_idx_t>(
                    i_block + sizeof(ext4_extent_header) * (index + 1)
                ));
    }
};
#pragma pack(pop)
/*
 * Structure of a directory entry
 */
#define EXT4_NAME_LEN 255

struct ext4_dir_entry
{
    uint32_t    inode;            /* Inode number */
    uint16_t    rec_len;        /* Directory entry length. Must be a multiple of 4 */
    uint16_t    name_len;        /* Name length */
    char    name[EXT4_NAME_LEN];    /* File name */
};

/*
 * Ext4 directory file types.  Only the low 3 bits are used.  The
 * other bits are reserved for now.
 */
enum ext4_dir_entry_2_filetype
{
    EXT4_FT_UNKNOWN  = 0x00,
    EXT4_FT_REG_FILE = 0x01,
    EXT4_FT_DIR      = 0x02,
    EXT4_FT_CHRDEV   = 0x03,
    EXT4_FT_BLKDEV   = 0x04,
    EXT4_FT_FIFO     = 0x05,
    EXT4_FT_SOCK     = 0x06,
    EXT4_FT_SYMLINK  = 0x07,
    EXT4_FT_MAX      = 0x08,
    EXT4_FT_DIR_CSUM = 0xDE,
};

/*
 * The new version of the directory entry.  Since EXT4 structures are
 * stored in intel byte order, and the name_len field could never be
 * bigger than 255 chars, it's safe to reclaim the extra byte for the
 * file_type field.
 */
struct ext4_dir_entry_2
{
    uint32_t    inode;            /* Inode number */
    uint16_t    rec_len;        /* Directory entry length */
    uint8_t     name_len;        /* Name length */
    uint8_t     file_type;        /* ext4_dir_entry_2_filetype */
    std::string name;           /* File name. changed for the convenience of working in cpp from char name[EXT4_NAME_LEN] */

    ext4_dir_entry_2_filetype get_file_type()
    {
        return static_cast<ext4_dir_entry_2_filetype>(file_type & 0b111);
    }
};

/*
 * Special struct for store 2 types of dir_entry
 */
struct ext4_dir_entry_generic
{
    bool        is_second_type;
    uint32_t    inode;            /* Inode number */
    uint16_t    rec_len;        /* Directory entry length */
    uint16_t    name_len;        /* Name length */
    uint8_t     file_type;        /* ext4_dir_entry_2_filetype */
    std::string name;           /* File name. changed for the convenience of working in cpp from char name[EXT4_NAME_LEN] */

    ext4_dir_entry_2_filetype get_file_type()
    {
        return static_cast<ext4_dir_entry_2_filetype>(file_type & 0b111);
    }
};
typedef ext4_dir_entry_generic* ext4_dir_entry_generic_t;

/*
 * This is a bogus directory entry at the end of each leaf block that
 * records checksums.
 */
struct ext4_dir_entry_tail
{
    uint32_t    det_reserved_zero1;    /* Pretend to be unused */
    uint16_t    det_rec_len;        /* 12 */
    uint8_t     det_reserved_zero2;    /* Zero name length */
    uint8_t     det_reserved_ft;    /* 0xDE, fake file type */
    uint32_t    det_checksum;        /* crc32c(uuid+inum+dirblock) */
};


/* Magic value in attribute blocks */
#define EXT4_XATTR_MAGIC 0xEA020000

/* Maximum number of references to one attribute block */
#define EXT4_XATTR_REFCOUNT_MAX 1024

/* Name indexes */
#define EXT4_XATTR_INDEX_USER              1
#define EXT4_XATTR_INDEX_POSIX_ACL_ACCESS  2
#define EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT 3
#define EXT4_XATTR_INDEX_TRUSTED           4
#define EXT4_XATTR_INDEX_LUSTRE            5
#define EXT4_XATTR_INDEX_SECURITY          6
#define EXT4_XATTR_INDEX_SYSTEM            7
#define EXT4_XATTR_INDEX_RICHACL           8
#define EXT4_XATTR_INDEX_ENCRYPTION        9
#define EXT4_XATTR_INDEX_HURD              10 /* Reserved for Hurd */

struct ext4_xattr_header
{
    uint32_t    h_magic;    /* magic number for identification */
    uint32_t    h_refcount;    /* reference count */
    uint32_t    h_blocks;    /* number of disk blocks used */
    uint32_t    h_hash;        /* hash value of all attributes */
    uint32_t    h_checksum;    /* crc32c(uuid+id+xattrblock) id = inum if refcount=1, blknum otherwise */
    uint32_t    h_reserved[3];    /* zero right now */
};

struct ext4_xattr_ibody_header
{
    uint32_t    h_magic;    /* magic number for identification */
};

struct ext4_xattr_entry
{
    uint8_t     e_name_len;        /* length of name */
    uint8_t     e_name_index;    /* attribute name index */
    uint16_t    e_value_offs;    /* offset in disk block of value */
    uint32_t    e_value_inum;    /* inode in which the value is stored */
    uint32_t    e_value_size;    /* size of attribute value */
    uint32_t    e_hash;            /* hash value of name and value */
    char        e_name[];        /* attribute name */
};

}; // end namespace


#endif