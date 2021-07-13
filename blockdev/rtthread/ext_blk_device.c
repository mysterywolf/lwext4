/*
 * RT-Thread Secure
 *
 * Copyright (c) 2021, Shanghai Real-Thread Electronic Technology Co., Ltd.
 *
 * All rights reserved.
 */

/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2021-07-09      linzhenxing   first version
 *
 */

#include <rtthread.h>
#include <rtdef.h>
#include <dfs.h>
#include <dfs_fs.h>
#include <dfs_file.h>
#include <ext4.h>
#include <ext4_debug.h>
#include <ext_blk_device.h>
#include <stdint.h>

static struct lwext4_part
{
    struct ext4_blockdev partitions[4];
} _part;
rt_device_t _mbr_device;
static rt_uint32_t _sector_size;

static int blockdev_open(struct ext4_blockdev *bdev)
{
    int r;
    rt_device_t device = _mbr_device;
    struct rt_device_blk_geometry geometry;
    RT_ASSERT(device);

    r = rt_device_open((rt_device_t)device, RT_DEVICE_OFLAG_RDWR);
    if (r != RT_EOK)
    {
        return r;
    }

    r = rt_device_control(device, RT_DEVICE_CTRL_BLK_GETGEOME, &geometry);
    if (RT_EOK == r)
    {
        bdev->part_offset = 0;
        bdev->part_size = geometry.sector_count * geometry.bytes_per_sector;
        _sector_size = geometry.bytes_per_sector;
        bdev->bdif->ph_bcnt = bdev->part_size / bdev->bdif->ph_bsize;
    }

    return r;
}

static int blockdev_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
                          uint32_t blk_cnt)
{
    int result;
    rt_device_t device = _mbr_device;
    RT_ASSERT(device);

    result = rt_device_read(device, blk_id * (bdev->bdif->ph_bsize / _sector_size),
                            buf, blk_cnt * (bdev->bdif->ph_bsize / _sector_size));

    if ((blk_cnt * (bdev->bdif->ph_bsize / _sector_size)) == result)
    {
        result = 0;
    }
    else
    {
        result = -EIO;
    }

    return result;
}

static int blockdev_bwrite(struct ext4_blockdev *bdev, const void *buf,
                           uint64_t blk_id, uint32_t blk_cnt)
{
    int result;
    rt_device_t device = _mbr_device;

    RT_ASSERT(device);

    result = rt_device_write(device, blk_id * (bdev->bdif->ph_bsize / _sector_size),
                             buf, blk_cnt * (bdev->bdif->ph_bsize / _sector_size));

    if ((blk_cnt * (bdev->bdif->ph_bsize / _sector_size)) == result)
    {
        result = 0;
    }
    else
    {
        result = -EIO;
    }

    return result;
}

static int blockdev_close(struct ext4_blockdev *bdev)
{
    return rt_device_close(_mbr_device);
}

static int blockdev_lock(struct ext4_blockdev *bdev)
{
    return 0;
}

static int blockdev_unlock(struct ext4_blockdev *bdev)
{
    return 0;
}

EXT4_BLOCKDEV_STATIC_INSTANCE(bdev, 512, 0, blockdev_open,
                              blockdev_bread, blockdev_bwrite, blockdev_close,
                              blockdev_lock, blockdev_unlock);

int get_partition(int part_id, struct ext4_blockdev *part)
{
    part->part_offset = _part.partitions[part_id].part_offset;
    part->part_size = _part.partitions[part_id].part_size;

    return 0;
}
void lwext4_init(rt_device_t mbr_device)
{
    _mbr_device = mbr_device;

    if (ext4_mbr_scan(&bdev, &_part) != EOK)
    {
        rt_kprintf("MBR scan failed!\n");
        return;
    }
}
