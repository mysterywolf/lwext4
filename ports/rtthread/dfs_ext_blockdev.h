/*
 * Copyright (c) 2006-2023, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author            Notes
 * 2023-01-15     bernard           add RT-Thread 5.0.x support
 */

#ifndef EXT_BD_H__
#define EXT_BD_H__

#include <rtthread.h>

struct dfs_ext4_blockdev 
{
    rt_device_t devid;
    struct ext4_blockdev bd;
    uint8_t ph_bbuf[4096];
    void *data;
};

struct ext4_blockdev *ext4_blockdev_from_devid(struct rt_device *devid);

struct dfs_ext4_blockdev *dfs_ext4_blockdev_create(rt_device_t devid);
int dfs_ext4_blockdev_destroy(struct dfs_ext4_blockdev *dbd);
struct dfs_ext4_blockdev *dfs_ext4_blockdev_from_bd(struct ext4_blockdev *bd);

#endif
