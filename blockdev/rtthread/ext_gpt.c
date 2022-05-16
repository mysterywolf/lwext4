/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author            Notes
 * 2022-05-06     linzhenxing       add gpt type
 */
#include <rtthread.h>
#include <dfs_fs.h>
#include "ext_gpt.h"
#include <drivers/mmcsd_core.h>

#include <ext4_config.h>
#include <ext4_types.h>
#include <ext4_misc.h>
#include <ext4_errno.h>
#include <ext4_debug.h>

#include <inttypes.h>
#include <string.h>

#define min(a, b) a < b ? a : b
static int force_gpt = 0;

static inline int efi_guidcmp (gpt_guid_t left, gpt_guid_t right)
{
    return memcmp(&left, &right, sizeof (gpt_guid_t));
}

static uint64_t last_lba(struct ext4_blockdev *bdev)
{
    RT_ASSERT(bdev != RT_NULL);
    return (bdev->bdif->ph_bcnt) - 1;
}

static inline int pmbr_part_valid(gpt_mbr_record *part)
{
    if (part->os_type != EFI_PMBR_OSTYPE_EFI_GPT)
    {
        goto invalid;
    }

    /* set to 0x00000001 (i.e., the LBA of the GPT Partition Header) */
    if ((uint32_t)(part->starting_lba) != GPT_PRIMARY_PARTITION_TABLE_LBA)
    {
        goto invalid;
    }

    return GPT_MBR_PROTECTIVE;
invalid:
    return 0;
}
/*
*
* return ret
* ret = 0, invalid mbr
* ret = 1, protect mbr
* ret = 2, hybrid mbr
*/
static int is_pmbr_valid(legacy_mbr *mbr, uint64_t total_sectors)
{
    uint32_t sz = 0;
    int i, part = 0, ret = 0; /* invalid by default */

    if (!mbr || (uint16_t)(mbr->signature) != MSDOS_MBR_SIGNATURE)
    {
        goto done;
    }

    for (i = 0; i < 4; i++)
    {
        ret = pmbr_part_valid(&mbr->partition_record[i]);
        if (ret == GPT_MBR_PROTECTIVE)
        {
            part = i;
            /*
             * Ok, we at least know that there's a protective MBR,
             * now check if there are other partition types for
             * hybrid MBR.
             */
            goto check_hybrid;
        }
    }

    if (ret != GPT_MBR_PROTECTIVE)
    {
        goto done;
    }

check_hybrid:
    for (i = 0; i < 4; i++)
    {
        if ((mbr->partition_record[i].os_type !=
            EFI_PMBR_OSTYPE_EFI_GPT) &&
            (mbr->partition_record[i].os_type != 0x00))
        {
            ret = GPT_MBR_HYBRID;
        }

    }

    /*
     * Protective MBRs take up the lesser of the whole disk
     * or 2 TiB (32bit LBA), ignoring the rest of the disk.
     * Some partitioning programs, nonetheless, choose to set
     * the size to the maximum 32-bit limitation, disregarding
     * the disk size.
     *
     * Hybrid MBRs do not necessarily comply with this.
     *
     * Consider a bad value here to be a warning to support dd'ing
     * an image from a smaller disk to a larger disk.
     */
    if (ret == GPT_MBR_PROTECTIVE)
    {
        sz = (uint32_t)(mbr->partition_record[part].size_in_lba);
        if (sz != (uint32_t) total_sectors - 1 && sz != 0xFFFFFFFF)
        {
            ext4_dbg(DEBUG_EXT_GPT, "GPT: mbr size in lba (0x%"PRIx32") different than whole disk", sz);
            ext4_dbg(DEBUG_EXT_GPT, " (0x%"PRIu64").\n", min(total_sectors - 1, 0xFFFFFFFF));                 
        }
    }

done:
    return ret;

}

static gpt_entry *alloc_read_gpt_entries(struct ext4_blockdev *bdev, gpt_header *gpt)
{
    size_t count;
    gpt_entry *pte;

    if (!gpt)
    {
        return RT_NULL;
    }

    count = (size_t)(gpt->num_partition_entries) * (gpt->sizeof_partition_entry);
    if (!count)
    {
        return RT_NULL;
    }

    pte = rt_malloc(count);
    if (!pte)
    {
        return RT_NULL;
    }

    if (ext4_block_readbytes(bdev, (size_t)(gpt->partition_entry_lba) * 512,(uint8_t *)pte, count) != RT_EOK)
    {
        rt_free(pte);
        return RT_NULL;
    }
    return pte;

}

static gpt_header *alloc_read_gpt_header(struct ext4_blockdev *bdev, uint64_t lba)
{
    gpt_header *gpt;

    gpt = rt_malloc(512);
    if (!gpt)
    {
        return RT_NULL;
    }

    if (ext4_block_readbytes(bdev, lba * 512, (uint8_t *)gpt, 512) != RT_EOK)
    {
        rt_free(gpt);
        return RT_NULL;
    }

    return gpt;
}

static int is_gpt_valid(struct ext4_blockdev *bdev, uint64_t lba, gpt_header **gpt, gpt_entry **ptes)
{
    uint64_t lastlba;

    if (!ptes)
    {
        return 0;
    }

    if (!(*gpt = alloc_read_gpt_header(bdev, lba)))
    {
        return 0;
    }

    /* Check the GUID Partition Table signature */
    if ((uint64_t)((*gpt)->signature) != GPT_HEADER_SIGNATURE)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GUID Partition Table Header signature is wrong: 0x%"PRIu64" !=", 
            (uint64_t)((*gpt)->signature));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)GPT_HEADER_SIGNATURE);
        goto fail;
    }

    /* Check that the my_lba entry points to the LBA that contains
     * the GUID Partition Table */
    if ((uint64_t)((*gpt)->my_lba) != lba)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT my_lba incorrect: 0x%"PRIu64" !=",
             (uint64_t)((*gpt)->my_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)lba);
        goto fail;
    }

    /* Check the first_usable_lba and last_usable_lba are
     * within the disk.
     */
    lastlba = last_lba(bdev);
    if ((uint64_t)((*gpt)->first_usable_lba) > lastlba)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT: first_usable_lba incorrect: 0x%"PRIu64" >",
             ((uint64_t)((*gpt)->first_usable_lba)));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", lastlba);
        goto fail;
    }

    if ((uint64_t)((*gpt)->last_usable_lba) > lastlba)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT: last_usable_lba incorrect: 0x%"PRIu64" >",
             (uint64_t)((*gpt)->last_usable_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", lastlba);
        goto fail;
    }

    if ((uint64_t)((*gpt)->last_usable_lba) < (uint64_t)((*gpt)->first_usable_lba))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT: last_usable_lba incorrect: 0x%"PRIu64" >",
             (uint64_t)((*gpt)->last_usable_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)((*gpt)->first_usable_lba));
        goto fail;
    }

    /* Check that sizeof_partition_entry has the correct value */
    if ((uint32_t)((*gpt)->sizeof_partition_entry) != sizeof(gpt_entry))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GUID Partition Entry Size check failed.\n");
        goto fail;
    }

    if (!(*ptes = alloc_read_gpt_entries(bdev, *gpt)))
        goto fail;


    /* We're done, all's well */
    return 1;

 fail:
    rt_free(*gpt);
    *gpt = RT_NULL;
    return 0;
}

/**
 * is_pte_valid() - tests one PTE for validity
 * @pte:pte to check
 * @lastlba: last lba of the disk
 *
 * Description: returns 1 if valid,  0 on error.
 */
static inline int is_pte_valid(const gpt_entry *pte, const size_t lastlba)
{
    if ((!efi_guidcmp(pte->partition_type_guid, NULL_GUID)) ||
        (uint64_t)(pte->starting_lba) > lastlba         ||
        (uint64_t)(pte->ending_lba)   > lastlba)
    {
        return 0;
    }

    return 1;
}

/**
 * compare_gpts() - Search disk for valid GPT headers and PTEs
 * @pgpt: primary GPT header
 * @agpt: alternate GPT header
 * @lastlba: last LBA number
 *
 * Description: Returns nothing.  Sanity checks pgpt and agpt fields
 * and prints warnings on discrepancies.
 *
 */
static void compare_gpts(gpt_header *pgpt, gpt_header *agpt, uint64_t lastlba)
{
    int error_found = 0;
    if (!pgpt || !agpt)
        return;

    if ((uint64_t)(pgpt->my_lba) != (uint64_t)(agpt->alternate_lba))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:Primary header LBA != Alt. header alternate_lba\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(pgpt->my_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)(agpt->alternate_lba));
        error_found++;
    }

    if ((uint64_t)(pgpt->alternate_lba) != (uint64_t)(agpt->my_lba))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:Primary header alternate_lba != Alt. header my_lba\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(pgpt->alternate_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)(agpt->my_lba));
        error_found++;
    }

    if ((uint64_t)(pgpt->first_usable_lba) != (uint64_t)(agpt->first_usable_lba))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:first_usable_lbas don't match.\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(pgpt->first_usable_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)(agpt->first_usable_lba));
        error_found++;
    }

    if ((uint64_t)(pgpt->last_usable_lba) != (uint64_t)(agpt->last_usable_lba))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:last_usable_lbas don't match.\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(pgpt->last_usable_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", (uint64_t)(agpt->last_usable_lba));
        error_found++;
    }

    if (efi_guidcmp(pgpt->disk_guid, agpt->disk_guid))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:disk_guids don't match.\n");
        error_found++;
    }

    if ((pgpt->num_partition_entries) != (agpt->num_partition_entries))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:num_partition_entries don't match: "
               "0x%"PRIx32" !=", (pgpt->num_partition_entries));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIx32"\n", (agpt->num_partition_entries));
        error_found++;
    }
    if ((pgpt->sizeof_partition_entry) != (agpt->sizeof_partition_entry))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:sizeof_partition_entry values don't match: "
               "0x%"PRIx32" !=", (pgpt->sizeof_partition_entry));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIx32"\n", (agpt->sizeof_partition_entry));
        error_found++;
    }
    if ((pgpt->partition_entry_array_crc32) != (agpt->partition_entry_array_crc32))
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:partition_entry_array_crc32 values don't match: "
               "0x%"PRIx32" !=", (pgpt->partition_entry_array_crc32));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIx32"\n", (agpt->partition_entry_array_crc32));
        error_found++;
    }
    if ((pgpt->alternate_lba) != lastlba)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:Primary header thinks Alt. header is not at the end of the disk.\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(pgpt->alternate_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", lastlba);
        error_found++;
    }

    if ((agpt->my_lba) != lastlba)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT:Alternate GPT header not at the end of the disk.\n");
        ext4_dbg(DEBUG_EXT_GPT, "GPT:0x%"PRIu64" !=", (uint64_t)(agpt->my_lba));
        ext4_dbg(DEBUG_EXT_GPT, " 0x%"PRIu64"\n", lastlba);
        error_found++;
    }

    if (error_found)
    {
        ext4_dbg(DEBUG_EXT_GPT, "GPT: Use GNU Parted to correct GPT errors.\n");
    }

    return;
}

/**
 * find_valid_gpt() - Search disk for valid GPT headers and PTEs
 * @state: disk parsed partitions
 * @gpt: GPT header ptr, filled on return.
 * @ptes: PTEs ptr, filled on return.
 *
 * Description: Returns 1 if valid, 0 on error.
 * If valid, returns pointers to newly allocated GPT header and PTEs.
 * Validity depends on PMBR being valid (or being overridden by the
 * 'gpt' kernel command line option) and finding either the Primary
 * GPT header and PTEs valid, or the Alternate GPT header and PTEs
 * valid.  If the Primary GPT header is not valid, the Alternate GPT header
 * is not checked unless the 'gpt' kernel command line option is passed.
 * This protects against devices which misreport their size, and forces
 * the user to decide to use the Alternate GPT.
 */
static int find_valid_gpt(struct ext4_blockdev *bdev, gpt_header **gpt,
              gpt_entry **ptes)
{
    int good_pgpt = 0, good_agpt = 0, good_pmbr = 0;
    gpt_header *pgpt = RT_NULL, *agpt = RT_NULL;
    gpt_entry *pptes = RT_NULL, *aptes = RT_NULL;
    legacy_mbr *legacymbr;
    size_t total_sectors = 0;
    uint64_t lastlba = 0;
    int status = 0;

    if (!ptes)
    {
        return 0;
    }

    lastlba = last_lba(bdev);
    total_sectors = last_lba(bdev) + 1;

    if (!force_gpt)
    {
        /* This will be added to the EFI Spec. per Intel after v1.02. */
        legacymbr = rt_malloc(512);
        if (!legacymbr)
        {
            goto fail;
        }

        status = ext4_block_readbytes(bdev, 0, (uint8_t *)legacymbr, 512);
        if (status != RT_EOK)
        {
            ext4_dbg(DEBUG_EXT_GPT, "status:%d\n", status);
            goto fail;
        }

        good_pmbr = is_pmbr_valid(legacymbr, total_sectors);
        rt_free(legacymbr);

        if (!good_pmbr)
        {
            goto fail;
        }

        ext4_dbg(DEBUG_EXT_GPT, "Device has a %s MBR\n",
             good_pmbr == GPT_MBR_PROTECTIVE ?
                        "protective" : "hybrid");
    }

    good_pgpt = is_gpt_valid(bdev, GPT_PRIMARY_PARTITION_TABLE_LBA,
                 &pgpt, &pptes);
    if (good_pgpt)
    {

        good_agpt = is_gpt_valid(bdev, (pgpt->alternate_lba), &agpt, &aptes);
        if (!good_agpt && force_gpt)
        {
                good_agpt = is_gpt_valid(bdev, lastlba, &agpt, &aptes);
        }

        /* The obviously unsuccessful case */
        if (!good_pgpt && !good_agpt)
        {
                goto fail;
        }

        compare_gpts(pgpt, agpt, lastlba);

        /* The good cases */
        if (good_pgpt)
        {
            *gpt  = pgpt;
            *ptes = pptes;
            rt_free(agpt);
            rt_free(aptes);
            if (!good_agpt)
            {
                ext4_dbg(DEBUG_EXT_GPT, "Alternate GPT is invalid, using primary GPT.\n");
            }
            return 1;
        }
        else if (good_agpt)
        {
            *gpt  = agpt;
            *ptes = aptes;
            rt_free(pgpt);
            rt_free(pptes);
            ext4_dbg(DEBUG_EXT_GPT, "Primary GPT is invalid, using alternate GPT.\n");
                return 1;
        }
    }

 fail:
        rt_free(pgpt);
        rt_free(agpt);
        rt_free(pptes);
        rt_free(aptes);
        *gpt = RT_NULL;
        *ptes = RT_NULL;
        return 0;
}
static gpt_header *_gpt;
static gpt_entry *_ptes;
int ext_check_gpt(struct ext4_blockdev *bdev)
{
    if (!find_valid_gpt(bdev, &_gpt, &_ptes) || !_gpt || !_ptes)
    {
        rt_free(_gpt);
        rt_free(_ptes);
        return -1;
    }
    return 0;
}

int ext_get_partition_param(struct ext4_blockdev *bdev, struct ext4_gpt_bdevs *bdevs, uint32_t pindex)
{
    if (!is_pte_valid(&_ptes[pindex], last_lba(bdev)))
    {
        return -1;
    }

    bdevs->partitions[pindex].bdif = bdev->bdif;
    bdevs->partitions[pindex].part_offset =
        (off_t)(_ptes[pindex].starting_lba) * 512;
    bdevs->partitions[pindex].part_size = (_ptes[pindex].ending_lba) - (_ptes[pindex].starting_lba) + 1ULL;;

    ext4_dbg(DEBUG_EXT_GPT, "found part[%x],", pindex);
    ext4_dbg(DEBUG_EXT_GPT, " begin(sector): 0x%"PRIu64",", _ptes[pindex].starting_lba);
    ext4_dbg(DEBUG_EXT_GPT, " end(sector):0x%"PRIu64" size: ", _ptes[pindex].ending_lba);             
    if ((bdevs->partitions[pindex].part_size >> 11) == 0)
        ext4_dbg(DEBUG_EXT_GPT, "0x%"PRIu64"%s", bdevs->partitions[pindex].part_size >> 1, "KB\n"); /* KB */
    else
    {
        unsigned int part_size;
        part_size = bdevs->partitions[pindex].part_size >> 11;                /* MB */
        if ((part_size >> 10) == 0)
            ext4_dbg(DEBUG_EXT_GPT, "%x.%"PRIu64"%s", part_size, (bdevs->partitions[pindex].part_size >> 1) & 0x3FF, "MB\n");
        else
            ext4_dbg(DEBUG_EXT_GPT, "%x.%"PRIu64"%s", part_size >> 10, bdevs->partitions[pindex].part_size & 0x3FF, "GB\n");
    }
    return 0;
}

void ext_gpt_free()
{
    rt_free(_ptes);
    rt_free(_gpt);
}

int ext4_gpt_scan(struct ext4_blockdev *parent, struct ext4_gpt_bdevs *bdevs)
{
    int r;
    size_t i;

    memset(bdevs, 0, sizeof(struct ext4_gpt_bdevs));
    r = ext4_block_init(parent);
    if (r != RT_EOK)
    {
        return r;
    }
    
    r = ext_check_gpt(parent);
    if (r != RT_EOK)
    {
        goto blockdev_fini;
    }

    for (i = 0; i < 128; i++)
    {
        r = ext_get_partition_param(parent, bdevs, i);
        if (r != RT_EOK)
        {
            r = RT_EOK;
            goto blockdev_fini;
        }
    }

blockdev_fini:
    ext4_block_fini(parent);
    ext_gpt_free();
    return r;
}
