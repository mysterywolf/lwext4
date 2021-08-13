/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author            Notes
 * 2017-11-11     parai@foxmail.com base porting
 * 2018-06-02     parai@foxmail.com fix mkfs issues
 * 2020-08-19     lizhirui          porting to ls2k
 * 2021-07-09     linzhenxing       modify for art pi smart
 */

#include <rtthread.h>
#include <rtdef.h>
#include <dfs.h>
#include <dfs_fs.h>
#include <dfs_file.h>

#include <ext_blk_device.h>

#include "dfs_ext.h"

#include "ext4.h"
#include "ext4_mkfs.h"
#include "ext4_config.h"
#include "ext4_blockdev.h"
#include "ext4_errno.h"
#include "ext4_mbr.h"
#include "ext4_super.h"

static int blockdev_open(struct ext4_blockdev *bdev);
static int blockdev_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
             uint32_t blk_cnt);
static int blockdev_bwrite(struct ext4_blockdev *bdev, const void *buf,
              uint64_t blk_id, uint32_t blk_cnt);
static int blockdev_close(struct ext4_blockdev *bdev);
static int blockdev_lock(struct ext4_blockdev *bdev);
static int blockdev_unlock(struct ext4_blockdev *bdev);

EXT4_BLOCKDEV_STATIC_INSTANCE(ext4_blkdev, 4096, 0, blockdev_open,
                  blockdev_bread, blockdev_bwrite, blockdev_close,
                  blockdev_lock, blockdev_unlock);

#if RT_DFS_EXT_DRIVES > 1
EXT4_BLOCKDEV_STATIC_INSTANCE(ext4_blkdev1, 4096, 0, blockdev_open,
                  blockdev_bread, blockdev_bwrite, blockdev_close,
                  blockdev_lock, blockdev_unlock);
#endif
#if RT_DFS_EXT_DRIVES > 2
EXT4_BLOCKDEV_STATIC_INSTANCE(ext4_blkdev2, 4096, 0, blockdev_open,
                  blockdev_bread, blockdev_bwrite, blockdev_close,
                  blockdev_lock, blockdev_unlock);
#endif
#if RT_DFS_EXT_DRIVES > 3
EXT4_BLOCKDEV_STATIC_INSTANCE(ext4_blkdev3, 4096, 0, blockdev_open,
                  blockdev_bread, blockdev_bwrite, blockdev_close,
                  blockdev_lock, blockdev_unlock);
#endif

#if RT_DFS_EXT_DRIVES > 4
#error dfs_ext by default support only 4 partitions!
#endif
static rt_device_t disk[RT_DFS_EXT_DRIVES] = {0};
static rt_size_t   disk_sector_size[RT_DFS_EXT_DRIVES] = {0};

static struct ext4_blockdev * const ext4_blkdev_list[RT_DFS_EXT_DRIVES] =
{
    &ext4_blkdev,
#if RT_DFS_EXT_DRIVES > 1
    &ext4_blkdev1,
#endif
#if RT_DFS_EXT_DRIVES > 2
    &ext4_blkdev2,
#endif
#if RT_DFS_EXT_DRIVES > 3
    &ext4_blkdev3,
#endif
};

static rt_mutex_t ext_mutex = RT_NULL;
static rt_mutex_t ext4_mutex = RT_NULL;
static void ext_lock(void);
static void ext_unlock(void);

static struct ext4_lock ext4_lock_ops =
{
    ext_lock,
	ext_unlock
};

static void ext_lock(void)
{
	rt_err_t result = -RT_EBUSY;

    while (result == -RT_EBUSY)
    {
        result = rt_mutex_take(ext4_mutex, RT_WAITING_FOREVER);
    }

    if (result != RT_EOK)
    {
        RT_ASSERT(0);
    }
    return ;
}

static void ext_unlock(void)
{
	rt_mutex_release(ext4_mutex);
    return ;
}

static int get_disk(rt_device_t id)
{
    int index;

    for (index = 0; index < RT_DFS_EXT_DRIVES; index ++)
    {
        if (disk[index] == id)
            return index;
    }

    return -1;
}

static int get_bdev(struct ext4_blockdev * bdev)
{
    int index;

    for (index = 0; index < RT_DFS_EXT_DRIVES; index ++)
    {
        if (ext4_blkdev_list[index] == bdev)
            return index;
    }

    RT_ASSERT(0);

    return -1;
}

static int dfs_ext_mount(struct dfs_filesystem* fs, unsigned long rwflag, const void* data)
{
    int rc;
    int index;
    long partid = (long)data;
    char* img = fs->dev_id->parent.name;

	ext_mutex = rt_mutex_create("lwext",RT_IPC_FLAG_FIFO);
    if (ext_mutex == RT_NULL)
    {
        printf("create lwext mutex failed.\n");
        return -1;
    }
	ext4_mutex = rt_mutex_create("lwext4",RT_IPC_FLAG_FIFO);
    if (ext4_mutex == RT_NULL)
    {
        printf("create lwext4 mutex failed.\n");
        return -1;
    }

    /* get an empty position */
    index = get_disk(RT_NULL);
    if (index == -1)
    {
        rt_kprintf("dfs_ext_mount: get an empty position.\n");
        return -RT_EINVAL;
    }

    lwext4_init(fs->dev_id);
    if(partid >= 0 && partid <= 3)
    {
        get_partition(partid, ext4_blkdev_list[index]);
    }
    else
    {
        rt_kprintf("dfs_ext_mount: mount partid:%d ,the partid max is 3.\n", partid);
        ext4_blkdev_list[index]->part_offset = -1;
    }

    rc = ext4_device_register(ext4_blkdev_list[index], img);
    if(RT_EOK == rc)
    {
        disk[index] = fs->dev_id;

        rc = ext4_mount(img, fs->path, false);

        if(RT_EOK != rc)
        {
            disk[index] = NULL;
            rc = -rc;
            ext4_device_unregister(img);
            rt_kprintf("ext4 mount fail!(%d)\n",rc);
        }
		
		ext4_mount_setup_locks(fs->path, &ext4_lock_ops);

    }
    else
    {
        rt_kprintf("device register fail(%d)!\n",rc);
    }

    return rc;
}

static int dfs_ext_unmount(struct dfs_filesystem* fs)
{
    int  index;
    int rc;
    char* mp = fs->path; /*mount point */
    /* find the device index and then umount it */
    index = get_disk(fs->dev_id);
    if (index == -1) /* not found */
        return -RT_EINVAL;

    rc = ext4_umount(mp);

    return rc;
}

static int dfs_ext_mkfs(rt_device_t devid)
{
    int  index;
    int rc;
    static struct ext4_fs fs;
    static struct ext4_mkfs_info info = {
        .block_size = 4096,
        .journal = true,
    };
    char* img = devid->parent.name;

    if (devid == RT_NULL)
    {
        return -RT_EINVAL;
    }

    /* find the device index, already mount */
    index = get_disk(devid);
    if (index != -1)
        return -RT_EBUSY;

    index = get_disk(RT_NULL);
    if (index == -1) /* not found */
        return -RT_EINVAL;

    rc = ext4_device_register(ext4_blkdev_list[index], img);
    if(EOK == rc)
    {
        disk[index] = devid;

        /* try to open device */
        rt_device_open(devid, RT_DEVICE_OFLAG_RDWR);
        rc = ext4_mkfs(&fs, ext4_blkdev_list[index], &info, F_SET_EXT4);

        /* no matter what, unregister */
        disk[index] = NULL;
        ext4_device_unregister(img);
        /* close device */
        rt_device_close(devid);
    }

    rc = -rc;

    return rc;
}

static int dfs_ext_statfs(struct dfs_filesystem *fs, struct statfs *buf)
{
	struct ext4_sblock *sb = NULL;
	int error = RT_EOK;
	
	error = ext4_get_sblock(fs->path, &sb);
	if(error != RT_EOK)
	{
		return -error;
	}

	buf->f_bsize = ext4_sb_get_block_size(sb);
	buf->f_blocks = ext4_sb_get_blocks_cnt(sb);
	buf->f_bfree = ext4_sb_get_free_blocks_cnt(sb);
	return error;
	
}
static int dfs_ext_ioctl(struct dfs_fd* file, int cmd, void* args)
{
    return -RT_EIO;
}

static int dfs_ext_read(struct dfs_fd *fd, void *buf, size_t count)
{
    size_t bytesread = 0;
    int r;

    r = ext4_fread(fd->data, buf, count, &bytesread);
    if (0 != r)
    {
        bytesread = 0;
    }

    return bytesread;
}

static int dfs_ext_write(struct dfs_fd *fd, const void *buf, size_t count)
{
    size_t byteswritten = 0;
    int r;

    r = ext4_fwrite(fd->data, buf, count, &byteswritten);
    if (0 != r)
    {
        byteswritten = 0;
    }

    return byteswritten;
}

static int dfs_ext_flush(struct dfs_fd *fd)
{
	int error = RT_EOK;
	error = ext4_cache_flush(fd->fnode->path);
	if(error != RT_EOK)
	{
		return -error;
	}

	return error;
}

static int dfs_ext_lseek(struct dfs_fd* file, rt_off_t offset)
{
    int r;

    r = ext4_fseek(file->data, offset, SEEK_SET);

    return -r;
}

static int dfs_ext_close(struct dfs_fd* file)
{
    int r;

#ifdef RT_USING_SMART
    if (file->fnode->type == FT_DIRECTORY)
#else
    if (file->type == FT_DIRECTORY)
#endif
    {
        r = ext4_fclose(file->data);
        rt_free(file->data);
    }
    else
    {
        r = ext4_fclose(file->data);
        if(EOK == r)
        {
            rt_free(file->data);
        }
    }

    return -r;
}

static int dfs_ext_open(struct dfs_fd* file)
{
    int r = EOK;
    ext4_dir *dir;
    ext4_file *f;
    if (file->flags & O_DIRECTORY)
    {
        if (file->flags & O_CREAT)
        {
#ifdef RT_USING_SMART
            r = ext4_dir_mk(file->fnode->path);
#else
            r = ext4_dir_mk(file->path);
#endif
        }
        if(EOK == r)
        {
            dir = rt_malloc(sizeof(ext4_dir));
#ifdef RT_USING_SMART
            r = ext4_dir_open(dir, file->fnode->path);
#else
            r = ext4_dir_open(dir, file->path);
#endif
            if(EOK == r)
            {
                file->data = dir;
            }
            else
            {
                rt_free(dir);
            }
        }
    }
    else
    {
        f = rt_malloc(sizeof(ext4_file));
#ifdef RT_USING_SMART
        r = ext4_fopen2(f, file->fnode->path, file->flags);
#else
        r = ext4_fopen2(f, file->path, file->flags);
#endif


        if(EOK == r)
        {
            file->data = f;
        }
        else
        {
            rt_free(f);
        }
    }
    return -r;
}

static int dfs_ext_unlink(struct dfs_filesystem *fs, const char *pathname)
{
    int r;

    r = ext4_fremove(pathname);

    return -r;
}

static int dfs_ext_stat(struct dfs_filesystem* fs, const char *path, struct stat *st)
{
    int r;

    union {
        ext4_dir dir;
        ext4_file f;
    } var;

    r = ext4_dir_open(&(var.dir), path);

    if(0 == r)
    {
        (void) ext4_dir_close(&(var.dir));
        st->st_mode = S_IFDIR;
        st->st_size = 0;
    }
    else
    {
        r = ext4_fopen(&(var.f), path, "rb");
        if( 0 == r)
        {
            st->st_mode = S_IFREG;
            st->st_size = ext4_fsize(&(var.f));
            (void)ext4_fclose(&(var.f));
        }
    }

    return -r;
}

static int dfs_ext_getdents(struct dfs_fd* file, struct dirent* dirp, rt_uint32_t count)
{
    int index;
    struct dirent *d;
    const ext4_direntry * rentry;

    /* make integer count */
    count = (count / sizeof(struct dirent)) * sizeof(struct dirent);
    if (count == 0)
        return -RT_EINVAL;

    index = 0;
    while (1)
    {
        d = dirp + index;

        rentry = ext4_dir_entry_next(file->data);
        if(NULL != rentry)
        {
            strncpy(d->d_name, rentry->name, DFS_PATH_MAX);
            if(EXT4_DE_DIR == rentry->inode_type)
            {
                d->d_type = DT_DIR;
            }
            else
            {
                d->d_type = DT_REG;
            }
            d->d_namlen = (rt_uint8_t)rentry->name_length;
            d->d_reclen = (rt_uint16_t)sizeof(struct dirent);

            index ++;
            if (index * sizeof(struct dirent) >= count)
                break;

        }
        else
        {
            break;
        }
    }

    file->pos += index * sizeof(struct dirent);

    return index * sizeof(struct dirent);
}

static int dfs_ext_rename  (struct dfs_filesystem *fs, const char *oldpath, const char *newpath)
{
    int r;

    r = ext4_frename(oldpath, newpath);

    return -r;
}

static const struct dfs_file_ops _ext_fops =
{
    dfs_ext_open,
    dfs_ext_close,
    dfs_ext_ioctl,
    dfs_ext_read,
    dfs_ext_write,
    dfs_ext_flush,
    dfs_ext_lseek,
    dfs_ext_getdents,
};

static const struct dfs_filesystem_ops _ext_fs =
{
    "ext",
    DFS_FS_FLAG_DEFAULT,
    &_ext_fops,

    dfs_ext_mount,
    dfs_ext_unmount,
    dfs_ext_mkfs,
    dfs_ext_statfs, /* statfs */

    dfs_ext_unlink,
    dfs_ext_stat,
    dfs_ext_rename
};

int dfs_ext_init(void)
{
    /* register rom file system */
    dfs_register(&_ext_fs);
    return 0;
}
INIT_COMPONENT_EXPORT(dfs_ext_init);



static int blockdev_open(struct ext4_blockdev *bdev)
{
    int r;
    int index = get_bdev(bdev);
    rt_device_t device = disk[index];
    struct rt_device_blk_geometry geometry;

    RT_ASSERT(index < RT_DFS_EXT_DRIVES);
    RT_ASSERT(device);

    r = rt_device_open(device,RT_DEVICE_OFLAG_RDWR);

    if(r != RT_EOK)
    {
        return r;
    }


    r = rt_device_control(device, RT_DEVICE_CTRL_BLK_GETGEOME, &geometry);
    if(RT_EOK == r)
    {
        if(bdev->part_offset == -1)
        {
            bdev->part_offset = 0;
            bdev->part_size = geometry.sector_count*geometry.bytes_per_sector;
        }
        bdev->bdif->ph_bsize = geometry.block_size;
        disk_sector_size[index] = geometry.bytes_per_sector;
        bdev->bdif->ph_bcnt = bdev->part_size / bdev->bdif->ph_bsize;
    }

    return r;

}

static int blockdev_bread(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
             uint32_t blk_cnt)
{
    int result;
    int index = get_bdev(bdev);
    rt_device_t device = disk[index];
    RT_ASSERT(index < RT_DFS_EXT_DRIVES);
    RT_ASSERT(device);

    result = rt_device_read(device, blk_id*(bdev->bdif->ph_bsize/disk_sector_size[index]),
            buf, blk_cnt*(bdev->bdif->ph_bsize/disk_sector_size[index]));

    if((blk_cnt*(bdev->bdif->ph_bsize/disk_sector_size[index])) == result)
    {
        result = 0;
    }
    else
    {
        result = -RT_EIO;
    }

    return result;
}


static int blockdev_bwrite(struct ext4_blockdev *bdev, const void *buf,
              uint64_t blk_id, uint32_t blk_cnt)
{
    int result;
    int index = get_bdev(bdev);
    rt_device_t device = disk[index];

    RT_ASSERT(index < RT_DFS_EXT_DRIVES);
    RT_ASSERT(device);

    result = rt_device_write(device, blk_id*(bdev->bdif->ph_bsize/disk_sector_size[index]),
            buf, blk_cnt*(bdev->bdif->ph_bsize/disk_sector_size[index]));

    if((blk_cnt*(bdev->bdif->ph_bsize/disk_sector_size[index])) == result)
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
    int index = get_bdev(bdev);
    rt_device_t device = disk[index];

    RT_ASSERT(index < RT_DFS_EXT_DRIVES);
    RT_ASSERT(device);

    result = rt_device_close(device);

    return result;
}

static int blockdev_lock(struct ext4_blockdev *bdev)
{
	rt_err_t result = -RT_EBUSY;

    while (result == -RT_EBUSY)
    {
        result = rt_mutex_take(ext_mutex, RT_WAITING_FOREVER);
    }

    if (result != RT_EOK)
    {
        RT_ASSERT(0);
    }
    return 0;
}

static int blockdev_unlock(struct ext4_blockdev *bdev)
{
	rt_mutex_release(ext_mutex);
    return 0;
}
