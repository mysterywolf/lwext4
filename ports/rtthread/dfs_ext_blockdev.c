/*
 * Copyright (c) 2006-2023, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author            Notes
 * 2023-01-15     bernard           add RT-Thread 5.0.x support
 */

#include <rtthread.h>
#include <dfs_fs.h>

#include <ext4.h>
#include <ext4_errno.h>
#include <ext4_blockdev.h>

#include "dfs_ext.h"
#include "dfs_ext_blockdev.h"

static int blockdev_lock(struct ext4_blockdev *bdev);
static int blockdev_unlock(struct ext4_blockdev *bdev);
static int blockdev_open(struct ext4_blockdev *bdev);
static int blockdev_read(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id, uint32_t blk_cnt);
static int blockdev_write(struct ext4_blockdev *bdev, const void *buf, uint64_t blk_id, uint32_t blk_cnt);
static int blockdev_close(struct ext4_blockdev *bdev);

static rt_mutex_t bdevice_mutex = RT_NULL;

static int blockdev_lock(struct ext4_blockdev *bdev)
{
    rt_err_t result = -RT_EBUSY;

    if (bdevice_mutex == RT_NULL)
    {
        /* create block device mutex */
        bdevice_mutex = rt_mutex_create("ext_bd", RT_IPC_FLAG_PRIO);
        RT_ASSERT(bdevice_mutex != RT_NULL);
    }

    while (result == -RT_EBUSY)
    {
        result = rt_mutex_take(bdevice_mutex, RT_WAITING_FOREVER);
    }

    if (result != RT_EOK)
    {
        RT_ASSERT(0);
    }

    return 0;
}

static int blockdev_unlock(struct ext4_blockdev *bdev)
{
    rt_mutex_release(bdevice_mutex);

    return 0;
}

static int blockdev_open(struct ext4_blockdev *bdev)
{
    int r;
    struct dfs_ext4_blockdev *dbd;
    rt_device_t device = NULL;
    struct rt_device_blk_geometry geometry;

    dbd = dfs_ext4_blockdev_from_bd(bdev);
    if (!dbd) return -RT_EINVAL;

    device = dbd->devid;
    RT_ASSERT(device != NULL);

    r = rt_device_open(device, RT_DEVICE_OFLAG_RDWR);
    if (r != RT_EOK)
    {
        return r;
    }

    r = rt_device_control(device, RT_DEVICE_CTRL_BLK_GETGEOME, &geometry);
    if (r == RT_EOK)
    {
        if (geometry.block_size != geometry.bytes_per_sector)
        {
            rt_kprintf("block device: block size != bytes_per_sector\n");
            rt_device_close(device);
            return -RT_EIO;
        }

        bdev->part_offset = 0;
        bdev->part_size = geometry.sector_count * geometry.bytes_per_sector;
        bdev->bdif->ph_bsize = geometry.block_size;
        bdev->bdif->ph_bcnt = bdev->part_size / bdev->bdif->ph_bsize;
    }
    else
    {
        rt_kprintf("block device: get geometry failed!\n");
        rt_device_close(device);
        return -RT_EIO;
    }

    return r;
}

static int blockdev_read(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
                          uint32_t blk_cnt)
{
    int result;
    struct dfs_ext4_blockdev *dbd;
    rt_device_t device = NULL;

    dbd = dfs_ext4_blockdev_from_bd(bdev);
    if (!dbd) return -RT_EINVAL;

    device = dbd->devid;
    RT_ASSERT(device != NULL);

    result = rt_device_read(device, blk_id, buf, blk_cnt);
    if (result == blk_cnt)
    {
        result = 0;
    }
    else
    {
        result = -RT_EIO;
    }

    return result;
}

static int blockdev_write(struct ext4_blockdev *bdev, const void *buf,
                           uint64_t blk_id, uint32_t blk_cnt)
{
    int result;
    struct dfs_ext4_blockdev *dbd;
    rt_device_t device = NULL;

    dbd = dfs_ext4_blockdev_from_bd(bdev);
    if (!dbd) return -RT_EINVAL;

    device = dbd->devid;
    RT_ASSERT(device != NULL);

    result = rt_device_write(device, blk_id, buf, blk_cnt);
    if (result == blk_cnt)
    {
        result = 0;
    }
    else
    {
        result = -RT_EIO;
    }

    return result;
}

static int blockdev_close(struct ext4_blockdev *bdev)
{
    int result;
    struct dfs_ext4_blockdev *dbd;
    rt_device_t device = NULL;

    dbd = dfs_ext4_blockdev_from_bd(bdev);
    if (!dbd) return -RT_EINVAL;

    device = dbd->devid;
    RT_ASSERT(device != NULL);

    result = rt_device_close(device);

    return result;
}

int dfs_ext4_blockdev_init(struct dfs_ext4_blockdev* dbd, rt_device_t devid)
{
    uint8_t *ph_bbuf = NULL;
    struct ext4_blockdev *bd = NULL;
    struct ext4_blockdev_iface *iface = NULL;

    if (dbd && devid)
    {
        dbd->devid = devid;

        bd = &dbd->bd;
        iface = (struct ext4_blockdev_iface *)rt_calloc(1, sizeof(struct ext4_blockdev_iface));
        if (iface == NULL) return -RT_ENOMEM;

        bd->bdif = iface;
        ph_bbuf = &dbd->ph_bbuf[0];

        iface->open = blockdev_open;
        iface->bread = blockdev_read;
        iface->bwrite = blockdev_write;
        iface->close = blockdev_close;
        iface->lock = blockdev_lock,
        iface->unlock = blockdev_unlock;
        iface->ph_bsize = 4096;
        iface->ph_bcnt = 0;
        iface->ph_bbuf = ph_bbuf;

        bd->bdif = iface;
        bd->part_offset = 0;
        bd->part_size = 0;
    }

    return 0;
}

struct dfs_ext4_blockdev *dfs_ext4_blockdev_from_bd(struct ext4_blockdev *bd)
{
    struct dfs_ext4_blockdev *dbd = NULL;

    if (bd)
    {
        dbd = rt_container_of(bd, struct dfs_ext4_blockdev, bd);
    }

    return dbd;
}

struct dfs_ext4_blockdev *dfs_ext4_blockdev_create(rt_device_t devid)
{
    struct dfs_ext4_blockdev *dbd = NULL;

    dbd = (struct dfs_ext4_blockdev*) rt_calloc(1, sizeof(struct dfs_ext4_blockdev));
    if (dbd)
    {
        dfs_ext4_blockdev_init(dbd, devid);
    }

    return dbd;
}

int dfs_ext4_blockdev_destroy(struct dfs_ext4_blockdev *dbd)
{
    int ret = -1;

    if (dbd)
    {
        rt_free(dbd->bd.bdif);
        rt_free(dbd);
        ret = 0;
    }

    return ret;
}
