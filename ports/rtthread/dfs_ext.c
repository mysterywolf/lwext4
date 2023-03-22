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
 * 2023-01-15     bernard           add RT-Thread 5.0.x support
 */

#include <rtthread.h>
#include <string.h>
#include <dfs.h>
#include <dfs_fs.h>
#include <dfs_file.h>

#include "ext4.h"
#include "ext4_mkfs.h"
#include "ext4_config.h"
#include "ext4_blockdev.h"
#include "ext4_errno.h"
#include "ext4_mbr.h"
#include "ext4_super.h"
#include "ext4_debug.h"
#include "ext4_inode.h"

#include "dfs_ext.h"
#include "dfs_ext_blockdev.h"

static rt_mutex_t ext4_mutex = RT_NULL;

static void ext4_lock(void);
static void ext4_unlock(void);

static struct ext4_lock ext4_lock_ops =
{
    ext4_lock,
    ext4_unlock
};

static void ext4_lock(void)
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

static void ext4_unlock(void)
{
    rt_mutex_release(ext4_mutex);
    return ;
}

rt_inline const char *get_fd_file(struct dfs_fd *fd)
{
    const char *fn = NULL;

    if (fd)
    {
#if (RTTHREAD_VERSION >= RT_VERSION_CHECK(5, 0, 0))
        fn = fd->vnode->fullpath;
#else
        fn = fd->path;
#endif
    }

    return fn;
}

static int dfs_ext_mount(struct dfs_filesystem *fs, unsigned long rwflag, const void *data)
{
    int rc = 0;
    struct ext4_blockdev *bd = NULL;
    struct dfs_ext4_blockdev *dbd = NULL;

    /* create dfs ext4 block device */
    dbd = dfs_ext4_blockdev_create(fs->dev_id);
    if (!dbd) return -RT_ERROR;

    bd = &dbd->bd;
    rc = ext4_mount(bd, fs->path, false);
    if (rc != RT_EOK)
    {
        dfs_ext4_blockdev_destroy(dbd);
        rc = -rc;
    }
    else
    {
        ext4_mount_setup_locks(fs->path, &ext4_lock_ops);
        /* set file system data to dbd */
        fs->data = (void*)dbd;
    }

    return rc;
}

static int dfs_ext_unmount(struct dfs_filesystem *fs)
{
    int rc;
    struct dfs_ext4_blockdev *dbd = NULL;

    dbd = (struct dfs_ext4_blockdev *)fs->data;
    if (dbd)
    {
        char *mp = fs->path; /*mount point */

        rc = ext4_umount(mp);
        if (rc == 0)
        {
            dfs_ext4_blockdev_destroy(dbd);
        }
    }

    return rc;
}

static int dfs_ext_mkfs(rt_device_t devid, const char *fs_name)
{
    int rc;
    static struct ext4_fs fs;
    static struct ext4_mkfs_info info =
    {
        .block_size = 4096,
        .journal = true,
    };
    struct ext4_blockdev *bd = NULL;
    struct dfs_ext4_blockdev *dbd = NULL;

    if (devid == RT_NULL)
    {
        return -RT_EINVAL;
    }

    /* create dfs ext4 block device */
    dbd = dfs_ext4_blockdev_create(devid);
    if (!dbd) return -RT_ERROR;

    /* get ext4 block device */
    bd = &dbd->bd;

    /* try to open device */
    rt_device_open(devid, RT_DEVICE_OFLAG_RDWR);
    rc = ext4_mkfs(&fs, bd, &info, F_SET_EXT4);

    /* no matter what, unregister */
    dfs_ext4_blockdev_destroy(dbd);
    /* close device */
    rt_device_close(devid);

    rc = -rc;
    return rc;
}

static int dfs_ext_statfs(struct dfs_filesystem *fs, struct statfs *buf)
{
    struct ext4_sblock *sb = NULL;
    int error = RT_EOK;

    error = ext4_get_sblock(fs->path, &sb);
    if (error != RT_EOK)
    {
        return -error;
    }

    buf->f_bsize = ext4_sb_get_block_size(sb);
    buf->f_blocks = ext4_sb_get_blocks_cnt(sb);
    buf->f_bfree = ext4_sb_get_free_blocks_cnt(sb);
    return error;

}
static int dfs_ext_ioctl(struct dfs_fd *fd, int cmd, void *args)
{
    int r = RT_EOK;
    switch (cmd)
    {
    case RT_FIOFTRUNCATE:
    {
        ext4_file *file = fd->data;
        uint64_t fpos, length;

        RT_ASSERT(file != RT_NULL);
        fpos = file->fpos;
        length = *(uint64_t *)args;
        if (length <= ext4_fsize(file))
        {
            file->fpos = length;
            r = ext4_ftruncate(file, length);
        }
        else
        {
            r = ext4_fseek(file, (int64_t)length, SEEK_SET);
        }
        file->fpos = fpos;
        return r;
    }
    case F_GETLK:
        return 0;
    case F_SETLK:
        return 0;
    }
    return -RT_EIO;
}

static int dfs_ext_read(struct dfs_fd *fd, void *buf, size_t count)
{
    size_t bytesread = 0;
    ext4_file *file = fd->data;
    int r;

    RT_ASSERT(file != RT_NULL);
    r = ext4_fread(file, buf, count, &bytesread);
    if (r != 0)
    {
        bytesread = 0;
    }
#if (RTTHREAD_VERSION >= RT_VERSION_CHECK(5, 0, 0))
    fd->pos = file->fpos;
#endif

    return bytesread;
}

static int dfs_ext_write(struct dfs_fd *fd, const void *buf, size_t count)
{
    size_t byteswritten = 0;
    ext4_file *file = fd->data;
    int r;

    RT_ASSERT(file != RT_NULL);
    r = ext4_fwrite(file, buf, count, &byteswritten);
    if (r != 0)
    {
        byteswritten = 0;
    }

#if (RTTHREAD_VERSION >= RT_VERSION_CHECK(5, 0, 0))
    fd->pos = file->fpos;
    fd->vnode->size = ext4_fsize(file);
#endif

    return byteswritten;
}

static int dfs_ext_flush(struct dfs_fd *fd)
{
    int error = RT_EOK;

    error = ext4_cache_flush(get_fd_file(fd));
    if (error != RT_EOK)
    {
        return -error;
    }

    return error;
}

static int dfs_ext_lseek(struct dfs_fd *fd, off_t offset)
{
    int r;
    ext4_file *file = fd->data;

    r = ext4_fseek(file, (int64_t)offset, SEEK_SET);
    if (r == RT_EOK)
    {
        return file->fpos;
    }

    return -r;
}

static int dfs_ext_close(struct dfs_fd *file)
{
    int r;

    r = ext4_fclose(file->data);
    if (r == EOK)
    {
        rt_free(file->data);
        file->data = NULL;
    }

    return -r;
}

static int dfs_ext_open(struct dfs_fd *file)
{
    int r = EOK;
    ext4_dir *dir;
    ext4_file *f;

    if (file->flags & O_DIRECTORY)
    {
        if (file->flags & O_CREAT)
        {
            r = ext4_dir_mk(get_fd_file(file));
        }
        if (EOK == r)
        {
            dir = rt_calloc(1, sizeof(ext4_dir));
            if (dir)
            {
                r = ext4_dir_open(dir, get_fd_file(file));
                if (r == EOK)
                {
                    file->data = dir;
                }
                else
                {
                    rt_free(dir);
                }
            }
        }
    }
    else
    {
        f = rt_calloc(1, sizeof(ext4_file));
        if (f)
        {
            r = ext4_fopen2(f, get_fd_file(file), file->flags);
            if (r == EOK)
            {
                file->data = f;
#if (RTTHREAD_VERSION >= RT_VERSION_CHECK(5, 0, 0))
                file->vnode->flags = f->flags;
                file->pos = f->fpos;
                file->vnode->size = (size_t)f->fsize;
#endif
            }
            else
            {
                rt_free(f);
            }
        }
    }
    return -r;
}

static int dfs_ext_unlink(struct dfs_filesystem *fs, const char *pathname)
{
    int r;
    char *stat_path;

    union
    {
        ext4_dir dir;
        ext4_file f;
    } var;

    if (fs->ops->flags & DFS_FS_FLAG_FULLPATH)
    {
        stat_path = (char *)pathname;
    }
    else
    {
        if (strlen(fs->path) != 1)
        {
            stat_path = malloc(strlen(fs->path) + strlen(pathname) + 1);
            snprintf((char *)stat_path, strlen(fs->path) + strlen(pathname) + 1, "%s%s", fs->path, pathname);
        }
        else
        {
            stat_path = (char *)pathname;
        }
    }

    r = ext4_dir_open(&(var.dir), stat_path);
    if (r == 0)
    {
        (void) ext4_dir_close(&(var.dir));
        ext4_dir_rm(stat_path);

    }
    else
    {
        r = ext4_fremove(stat_path);
    }

    return -r;
}

static int dfs_ext_stat(struct dfs_filesystem *fs, const char *path, struct stat *st)
{
    int r;
    uint32_t mode = 0;
    uint32_t uid;
    uint32_t gid;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    char *stat_path;
    struct ext4_inode inode;
    uint32_t ino = 0;
    uint32_t dev = 0;

    union
    {
        ext4_dir dir;
        ext4_file f;
    } var;

    if (fs->ops->flags & DFS_FS_FLAG_FULLPATH)
    {
        stat_path = (char *)path;
    }
    else
    {
        if (strlen(fs->path) != 1)
        {
            stat_path = malloc(strlen(fs->path) + strlen(path) + 1);
            snprintf((char *)stat_path, strlen(fs->path) + strlen(path) + 1, "%s%s", fs->path, path);
        }
        else
        {
            stat_path = (char *)path;
        }
    }

    r = ext4_dir_open(&(var.dir), stat_path);
    if (r == 0)
    {
        (void) ext4_dir_close(&(var.dir));
        ext4_mode_get(stat_path, &mode);
        ext4_owner_get(stat_path, &uid, &gid);
        ext4_atime_get(stat_path, &atime);
        ext4_mtime_get(stat_path, &mtime);
        ext4_ctime_get(stat_path, &ctime);

        if (ext4_raw_inode_fill(stat_path, &ino, &inode) == EOK)
        {
            dev = ext4_inode_get_dev(&inode);
        }
        st->st_dev = dev;
        st->st_ino = ino;
        st->st_mode = mode;
        st->st_size = var.dir.f.fsize;
        st->st_uid = uid;
        st->st_gid = gid;
        st->st_atime = atime;
        st->st_mtime = mtime;
        st->st_ctime = ctime;
    }
    else
    {
        r = ext4_fopen(&(var.f), stat_path, "rb");
        if (r == 0)
        {
            ext4_mode_get(stat_path, &mode);
            ext4_owner_get(stat_path, &uid, &gid);
            ext4_atime_get(stat_path, &atime);
            ext4_mtime_get(stat_path, &mtime);
            ext4_ctime_get(stat_path, &ctime);
            if (ext4_raw_inode_fill(stat_path, &ino, &inode) == EOK)
            {
                dev = ext4_inode_get_dev(&inode);
            }
            st->st_dev = dev;
            st->st_ino = ino;
            st->st_mode = mode;
            st->st_size = ext4_fsize(&(var.f));
            st->st_uid = uid;
            st->st_gid = gid;
            st->st_atime = atime;
            st->st_mtime = mtime;
            st->st_ctime = ctime;

            (void)ext4_fclose(&(var.f));
        }
    }

    return -r;
}

static int dfs_ext_getdents(struct dfs_fd *file, struct dirent *dirp, rt_uint32_t count)
{
    int index;
    struct dirent *d;
    const ext4_direntry *rentry;

    /* make integer count */
    count = (count / sizeof(struct dirent)) * sizeof(struct dirent);
    if (count == 0)
    {
        return -RT_EINVAL;
    }

    index = 0;
    while (1)
    {
        d = dirp + index;

        rentry = ext4_dir_entry_next(file->data);
        if (NULL != rentry)
        {
            strncpy(d->d_name, (char *)rentry->name, DFS_PATH_MAX);
            if (EXT4_DE_DIR == rentry->inode_type)
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

static int dfs_ext_rename(struct dfs_filesystem *fs, const char *oldpath, const char *newpath)
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
    if (ext4_mutex == RT_NULL)
    {
        ext4_mutex = rt_mutex_create("lwext4", RT_IPC_FLAG_FIFO);
        if (ext4_mutex == RT_NULL)
        {
            ext4_dbg(DEBUG_DFS_EXT, "create lwext mutex failed.\n");
            return -1;
        }
    }

    /* register rom file system */
    dfs_register(&_ext_fs);
    return 0;
}
INIT_COMPONENT_EXPORT(dfs_ext_init);
