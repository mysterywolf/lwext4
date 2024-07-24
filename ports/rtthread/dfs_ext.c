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

#include <string.h>

#include <rtthread.h>

#include <dfs.h>
#include <dfs_fs.h>
#include <dfs_file.h>
#include <dfs_mnt.h>
#include <dfs_dentry.h>

#include "ext4.h"
#include "ext4_mkfs.h"
#include "ext4_config.h"
#include "ext4_blockdev.h"
#include "ext4_errno.h"
#include "ext4_mbr.h"
#include "ext4_super.h"
#include "ext4_fs.h"
#include <ext4_mp.h>

#include "dfs_ext.h"
#include "dfs_ext_blockdev.h"

#ifdef RT_USING_PAGECACHE
#include "dfs_pcache.h"
#endif

#ifdef PKG_USING_DLOG
#include <dlog.h>
#else
#define DLOG(...)
#endif

struct dfs_ext4_vnode
{
    struct ext4_mountpoint *mp;
    struct ext4_inode_ref inode_ref;
};

struct dfs_ext4_file
{
    uint32_t type;  /* EXT4_DE_DIR or EXT4_DE_REG_FILE */
    union
    {
        ext4_file file;
        ext4_dir dir;
    } entry;
    struct dfs_ext4_vnode vnode;
};

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
    return;
}

static void ext4_unlock(void)
{
    rt_mutex_release(ext4_mutex);
    return;
}

static off_t dfs_ext_lseek(struct dfs_file *file, off_t offset, int whence);

#ifdef RT_USING_PAGECACHE
static ssize_t dfs_ext_page_read(struct dfs_file *file, struct dfs_page *page);
static ssize_t dfs_ext_page_write(struct dfs_page *page);

static struct dfs_aspace_ops dfs_ext_aspace_ops =
{
    .read = dfs_ext_page_read,
    .write = dfs_ext_page_write,
};
#endif

/* update vnode information */
rt_inline int ext4_vnode_update_info(struct dfs_vnode *vnode)
{
    if (vnode && vnode->data)
    {
        struct dfs_ext4_file *ext_file = (struct dfs_ext4_file *)vnode->data;

        vnode->mode = ext4_inode_get_mode(&ext_file->vnode.mp->fs.sb, ext_file->vnode.inode_ref.inode);
        vnode->uid = ext4_inode_get_uid(ext_file->vnode.inode_ref.inode);
        vnode->gid = ext4_inode_get_gid(ext_file->vnode.inode_ref.inode);
        vnode->atime.tv_sec = ext4_inode_get_access_time(ext_file->vnode.inode_ref.inode);
        vnode->mtime.tv_sec = ext4_inode_get_modif_time(ext_file->vnode.inode_ref.inode);
        vnode->ctime.tv_sec = ext4_inode_get_change_inode_time(ext_file->vnode.inode_ref.inode);
    }

    return 0;
}

/* file system ops */

static struct dfs_vnode *dfs_ext_lookup(struct dfs_dentry *dentry)
{
    char *fn = RT_NULL;
    struct dfs_vnode *vnode = RT_NULL;
    struct dfs_ext4_file *ext_file = RT_NULL;

    ext_file = (struct dfs_ext4_file *)rt_calloc(1, sizeof(struct dfs_ext4_file));
    if (ext_file)
    {
        fn = dfs_dentry_full_path(dentry);
        if (fn)
        {
            DLOG(msg, "ext", "vnode", DLOG_MSG, "dfs_vnode_create()");
            vnode = dfs_vnode_create();
            if (vnode)
            {
                ext_file->vnode.mp = ext4_get_inode_ref(fn, &(ext_file->vnode.inode_ref));
                if (ext_file->vnode.mp)
                {
                    /* found entry */
                    int type = ext4_inode_type(&(ext_file->vnode.mp->fs.sb), ext_file->vnode.inode_ref.inode);
                    switch (type)
                    {
                    case EXT4_INODE_MODE_FILE:
                        vnode->type = FT_REGULAR;
                        vnode->size = ext4_inode_get_size(&(ext_file->vnode.mp->fs.sb), ext_file->vnode.inode_ref.inode);
#ifdef RT_USING_PAGECACHE
                        vnode->aspace = dfs_aspace_create(dentry, vnode, &dfs_ext_aspace_ops);
#endif
                        break;
                    case EXT4_INODE_MODE_DIRECTORY:
                        vnode->type = FT_DIRECTORY;
                        vnode->size = 0;
                        break;
                    case EXT4_INODE_MODE_SOFTLINK:
                        vnode->type = FT_SYMLINK;
                        vnode->size = 0;
                        break;
                    }

                    vnode->nlink = 1;
                    DLOG(msg, "ext", "mnt", DLOG_MSG, "dfs_mnt_ref(dentry->mnt, name=%s)", dentry->mnt->fs_ops->name);
                    vnode->mnt = dentry->mnt;
                    vnode->data = (void *)ext_file;
                    ext_file->type = EXT4_DE_UNKNOWN;
                    rt_mutex_init(&vnode->lock, dentry->pathname, RT_IPC_FLAG_PRIO);

                    ext4_vnode_update_info(vnode);
                }
                else
                {
                    /* free vnode */
                    DLOG(msg, "ext", "vnode", DLOG_MSG, "dfs_vnode_destroy(no entry)");
                    dfs_vnode_destroy(vnode);
                    vnode = RT_NULL;
                }
            }
            rt_free(fn);
        }

        if (vnode == RT_NULL)
        {
            rt_free(ext_file);
        }
    }

    return vnode;
}

static struct dfs_vnode *dfs_ext_create_vnode(struct dfs_dentry *dentry, int type, mode_t mode)
{
    int ret = 0;
    char *fn = NULL;
    struct dfs_vnode *vnode = RT_NULL;
    struct dfs_ext4_file *ext_file = RT_NULL;
    int filetype = EXT4_DE_UNKNOWN;

    vnode = dfs_vnode_create();
    if (vnode)
    {
        fn = dfs_dentry_full_path(dentry);
        if (fn)
        {
            ext_file = (struct dfs_ext4_file *)rt_calloc(1, sizeof(struct dfs_ext4_file));
            if (ext_file)
            {
                if (type == FT_DIRECTORY)
                {
                    /* create dir */
                    ret = ext4_dir_mk(fn);
                    if (ret == EOK)
                    {
                        ext4_mode_set(fn, mode);
                        ext_file->vnode.mp = ext4_get_inode_ref(fn, &(ext_file->vnode.inode_ref));
                        if (ext_file->vnode.mp)
                        {
                            vnode->type = FT_DIRECTORY;
                            vnode->size = 0;
                        }
                        else
                        {
                            rt_kprintf("get inode ref failed: %s\n", fn);
                        }
                    }
                }
                else if (type == FT_REGULAR)
                {
                    ext4_file file;
                    /* create file */
                    if (!(mode & S_IFMT) || S_ISREG(mode))
                    {
                        ret = ext4_fopen2(&file, fn, O_CREAT);
                        if (ret == EOK)
                        {
                            ext4_fclose(&file);

                            ext4_mode_set(fn, mode);
                            ext_file->vnode.mp = ext4_get_inode_ref(fn, &(ext_file->vnode.inode_ref));
                            if (ext_file->vnode.mp)
                            {
                                vnode->type = FT_REGULAR;
                                vnode->size = ext4_inode_get_size(&(ext_file->vnode.mp->fs.sb), ext_file->vnode.inode_ref.inode);
                            }
#ifdef RT_USING_PAGECACHE
                            vnode->aspace = dfs_aspace_create(dentry, vnode, &dfs_ext_aspace_ops);
#endif
                        }
                    }
                    else
                    {
                        if (S_ISLNK(mode))
                        {
                            filetype = EXT4_DE_SYMLINK;
                        }
                        else if (S_ISDIR(mode))
                        {
                            filetype = EXT4_DE_DIR;
                        }
                        else if (S_ISCHR(mode))
                        {
                            filetype = EXT4_DE_CHRDEV;
                        }
                        else if (S_ISBLK(mode))
                        {
                            filetype = EXT4_DE_BLKDEV;
                        }
                        else if (S_ISFIFO(mode))
                        {
                            filetype = EXT4_DE_FIFO;
                        }
                        else if (S_ISSOCK(mode))
                        {
                            filetype = EXT4_DE_SOCK;
                        }

                        ret = ext4_mknod(fn, filetype, 0);
                    }
                }

                if (ret != EOK)
                {
                    rt_free(ext_file);
                    ext_file = NULL;

                    dfs_vnode_destroy(vnode);
                    vnode = NULL;
                }
                else
                {
                    DLOG(msg, "ext", "mnt", DLOG_MSG, "dfs_mnt_ref(dentry->mnt, name=%s)", dentry->mnt->fs_ops->name);
                    vnode->mnt = dentry->mnt;
                    vnode->data = (void *)ext_file;
                    vnode->mode = mode;
                    ext_file->type = filetype;
                    rt_mutex_init(&vnode->lock, dentry->pathname, RT_IPC_FLAG_PRIO);
                }
            }

            rt_free(fn);
            fn = NULL;
        }
        else
        {
            dfs_vnode_destroy(vnode);
            vnode = NULL;
        }
    }

    return vnode;
}

static int dfs_ext_free_vnode(struct dfs_vnode *vnode)
{
    if (vnode)
    {
        struct dfs_ext4_file *ext_file = (struct dfs_ext4_file *)vnode->data;
        if (ext_file)
        {
            if (ext_file->vnode.mp)
            {
                ext4_put_inode_ref(ext_file->vnode.mp, &(ext_file->vnode.inode_ref));
            }
            rt_mutex_detach(&vnode->lock);
            rt_free(ext_file);
            vnode->data = RT_NULL;
        }
    }

    return RT_EOK;
}

static int dfs_ext_mount(struct dfs_mnt *mnt, unsigned long rwflag, const void *data)
{
    int rc = 0;
    struct ext4_blockdev *bd = NULL;
    struct dfs_ext4_blockdev *dbd = NULL;

    /* create dfs ext4 block device */
    dbd = dfs_ext4_blockdev_create(mnt->dev_id);
    if (!dbd) return RT_NULL;

    bd = &dbd->bd;
    rc = ext4_mount(bd, mnt->fullpath, false);
    if (rc != EOK)
    {
        dfs_ext4_blockdev_destroy(dbd);
        rc = -rc;
    }
    else
    {
        ext4_mount_setup_locks(mnt->fullpath, &ext4_lock_ops);
        /* set file system data to dbd */
        dbd->data = bd->journal;
        bd->journal = 0;
        mnt->data = (void *)dbd;
    }

    return rc;
}

static int dfs_ext_unmount(struct dfs_mnt *mnt)
{
    int rc = EPERM;
    struct dfs_ext4_blockdev *dbd = NULL;

    dbd = (struct dfs_ext4_blockdev *)mnt->data;
    if (dbd)
    {
        rc = ext4_umount_mp(dbd->data);
        if (rc == 0)
        {
            dfs_ext4_blockdev_destroy(dbd);
            mnt->data = NULL;
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

static int dfs_ext_statfs(struct dfs_mnt *mnt, struct statfs *buf)
{
    struct ext4_sblock *sb = NULL;
    int error = RT_EOK;

    if (mnt)
    {
        error = ext4_get_sblock(mnt->fullpath, &sb);
        if (error != RT_EOK)
        {
            return -error;
        }

        buf->f_bsize = ext4_sb_get_block_size(sb);
        buf->f_blocks = ext4_sb_get_blocks_cnt(sb);
        buf->f_bfree = ext4_sb_get_free_blocks_cnt(sb);
        //TODO this is not accurate, because it is free blocks available to unprivileged user, but ...
        buf->f_bavail = buf->f_bfree;
    }

    return error;
}

/* file ops */

static ssize_t dfs_ext_read(struct dfs_file *file, void *buf, size_t count, off_t *pos)
{
    int r;
    size_t bytesread = 0;
    struct dfs_ext4_file *ext_file;

    if (file && file->data && file->vnode->size > *pos)
    {
        ext_file = (struct dfs_ext4_file *)file->data;
        if (ext_file->vnode.mp)
        {
            rt_mutex_take(&file->vnode->lock, RT_WAITING_FOREVER);
            dfs_ext_lseek(file, *pos, SEEK_SET);
            r = ext4_fread(&ext_file->entry.file, buf, count, &bytesread);
            if (r != 0)
            {
                bytesread = 0;
            }
            *pos = ext_file->entry.file.fpos;
            rt_mutex_release(&file->vnode->lock);
        }
    }

    return bytesread;
}

static ssize_t dfs_ext_write(struct dfs_file *file, const void *buf, size_t count, off_t *pos)
{
    int r;
    size_t byteswritten = 0;
    struct dfs_ext4_file *ext_file;

    if (file && file->data)
    {
        ext_file = (struct dfs_ext4_file *)file->data;
        if (ext_file->vnode.mp)
        {
            rt_mutex_take(&file->vnode->lock, RT_WAITING_FOREVER);
            dfs_ext_lseek(file, *pos, SEEK_SET);
            r = ext4_fwrite(&(ext_file->entry.file), buf, count, &byteswritten);
            if (r != 0)
            {
                byteswritten = 0;
            }

            file->vnode->size = ext4_fsize(&(ext_file->entry.file));
            *pos = ext_file->entry.file.fpos;
            rt_mutex_release(&file->vnode->lock);
        }
    }

    return byteswritten;
}

static int dfs_ext_flush(struct dfs_file *file)
{
    char *fn = RT_NULL;
    int error = RT_EOK;

    if (file && file->dentry)
    {
        fn = dfs_dentry_full_path(file->dentry);
        if (fn)
        {
            error = ext4_cache_flush(fn);

            rt_free(fn);
        }
    }

    if (error != RT_EOK)
    {
        error = -error;
    }

    return error;
}

static off_t dfs_ext_lseek(struct dfs_file *file, off_t offset, int whence)
{
    off_t ret = -EPERM;
    struct dfs_ext4_file *ext_file;

    if (file && file->data)
    {
        ext_file = (struct dfs_ext4_file *)file->data;
        rt_mutex_take(&file->vnode->lock, RT_WAITING_FOREVER);
        if (ext_file->type == EXT4_DE_DIR)
        {
            if (offset == 0)
            {
                ext4_dir_entry_rewind(&(ext_file->entry.dir));
                ret = 0;
            }
        }
        else if (ext_file->type == EXT4_DE_REG_FILE)
        {
            ret = generic_dfs_lseek(file, offset, whence);
            if (ret >= 0)
            {
                ext_file->entry.file.fpos = ret;
            }
        }
        rt_mutex_release(&file->vnode->lock);
    }

    return ret;
}

static int dfs_ext_close(struct dfs_file *file)
{
    int ret = 0;
    struct dfs_ext4_file *ext_file = RT_NULL;

    if (file)
    {
        RT_ASSERT(file->vnode->ref_count > 0);
        if (file->vnode->ref_count > 1)
        {
            return ret;
        }
        ext_file = (struct dfs_ext4_file *)file->data;
        if (ext_file)
        {
            if (ext_file->type == EXT4_DE_DIR)
            {
                ret = ext4_dir_close(&ext_file->entry.dir);
            }
            else if (ext_file->type == EXT4_DE_REG_FILE)
            {
                ret = ext4_fclose(&ext_file->entry.file);
            }

            if (ret == EOK)
            {
                ext_file->type = EXT4_DE_UNKNOWN;
                file->data = NULL;
            }
        }
    }

    return -ret;
}

static int dfs_ext_open(struct dfs_file *file)
{
    int ret = EOK;
    struct dfs_ext4_file *ext_file = RT_NULL;

    if (file && file->vnode)
    {
        ext_file = (struct dfs_ext4_file *)file->vnode->data;

        RT_ASSERT(file->vnode->ref_count > 0);
        if (ext_file && ext_file->type != EXT4_DE_UNKNOWN)
        {
            if (file->vnode->type == FT_DIRECTORY
                && !(file->flags & O_DIRECTORY))
            {
                return -ENOENT;
            }
            if (file->vnode->type == FT_DIRECTORY)
            {
                file->data = rt_calloc(1, sizeof(struct dfs_ext4_file));
                rt_memcpy(file->data, ext_file, sizeof(struct dfs_ext4_file));
                ext_file = (struct dfs_ext4_file *)file->data;
                ext_file->entry.dir.next_off = 0;
            }
            else
            {
                file->data = ext_file;
            }

            file->fpos = 0;
            return ret;
        }

        if (ext_file)
        {
            char *fn = NULL;

            fn = dfs_dentry_full_path(file->dentry);
            if (fn)
            {
                if (file->vnode->type == FT_DIRECTORY)
                {
                    /* open dir */
                    ret = ext4_dir_open(&ext_file->entry.dir, fn);
                    if (ret == EOK)
                    {
                        ext_file->type = EXT4_DE_DIR;
                        file->fpos = 0;
                    }
                }
                else
                {
                    /* open regular file */
                    ret = ext4_fopen2(&ext_file->entry.file, fn, file->flags);
                    if (ret == EOK)
                    {
                        ext_file->type = EXT4_DE_REG_FILE;
                        if (file->flags & O_TRUNC)
                        {
                            file->vnode->size = 0;
                        }
                        file->fpos = ext_file->entry.file.fpos;
                    }
                }

                if (ret == EOK)
                {
                    file->data = ext_file;
                }

                rt_free(fn);
            }
        }
    }
    else
    {
        ret = ENOENT;
    }

    return -ret;
}

static int dfs_ext_readlink(struct dfs_dentry *dentry, char *buf, int len)
{
    int ret = EOK;
    char *fn = NULL;

    if (dentry && buf)
    {
        fn = dfs_dentry_full_path(dentry);
        if (fn)
        {
            size_t size;
            ret = ext4_readlink(fn, buf, len, &size);
            rt_free(fn);
            if (ret == EOK)
            {
                buf[size] = '\0';
                return size;
            }
        }
        else
        {
            ret = ENOMEM;
        }
    }
    else
    {
        ret = EBADF;
    }

    return -ret;
}

static int dfs_ext_link(struct dfs_dentry *src_dentry, struct dfs_dentry *dst_dentry)
{
    char *src_path = NULL, *dst_path = NULL;

    src_path = dfs_dentry_full_path(src_dentry);
    dst_path = dfs_dentry_full_path(dst_dentry);

    if (src_path && dst_path)
    {
        ext4_flink(src_path, dst_path);

        rt_free(src_path);
        rt_free(dst_path);
    }

    return EOK;
}

static int dfs_ext_symlink(struct dfs_dentry *parent_dentry, const char *target, const char *linkpath)
{
    int ret = EOK;
    char *fn = NULL;

    if (parent_dentry && linkpath[0] != '/')
    {
        char *full = dfs_dentry_full_path(parent_dentry);
        if (full)
        {
            fn = dfs_normalize_path(full, linkpath);
            rt_free(full);
        }
    }
    else
    {
        fn = (char *)linkpath;
    }

    if (fn)
    {
        ret = ext4_fsymlink(target, fn);
        if (fn != linkpath)
            rt_free(fn);
    }
    else
    {
        ret = ENOMEM;
    }

    return -ret;
}

static int dfs_ext_unlink(struct dfs_dentry *dentry)
{
    int ret = EPERM;
    char *fn = NULL;
    struct dfs_ext4_file file;

    fn = dfs_dentry_full_path(dentry);
    if (fn)
    {
        ret = ext4_dir_open(&(file.entry.dir), fn);
        if (ret == 0)
        {
            ext4_dir_close(&(file.entry.dir));
            ret = ext4_dir_rm(fn);
        }
        else
        {
            ret = ext4_fremove(fn);
        }

        rt_free(fn);
    }

    return -ret;
}

static int dfs_ext_stat(struct dfs_dentry *dentry, struct stat *st)
{
    int ret = 0;
    char *stat_path;

    stat_path = dfs_dentry_full_path(dentry);
    if (stat_path)
    {
        struct ext4_inode_ref inode_ref;
        struct ext4_mountpoint *mp = ext4_get_inode_ref(stat_path, &inode_ref);

        if (mp)
        {
            st->st_mode = ext4_inode_get_mode(&mp->fs.sb, inode_ref.inode);
            st->st_uid = ext4_inode_get_uid(inode_ref.inode);
            st->st_gid = ext4_inode_get_gid(inode_ref.inode);
            if (S_ISDIR(st->st_mode))
            {
                st->st_size = ext4_inode_get_size(&mp->fs.sb, inode_ref.inode);
            }
            else
            {
#ifdef RT_USING_PAGECACHE
                st->st_size = (dentry->vnode && dentry->vnode->aspace) ? dentry->vnode->size : ext4_inode_get_size(&mp->fs.sb, inode_ref.inode);
#else
                st->st_size = ext4_inode_get_size(&mp->fs.sb, inode_ref.inode);
#endif
            }
            st->st_atime = ext4_inode_get_access_time(inode_ref.inode);
            st->st_mtime = ext4_inode_get_modif_time(inode_ref.inode);
            st->st_ctime = ext4_inode_get_change_inode_time(inode_ref.inode);

            st->st_dev = (dev_t)(dentry->mnt->dev_id);
            st->st_ino = inode_ref.index;

            st->st_blksize = ext4_sb_get_block_size(&mp->fs.sb);
            // man say st_blocks is number of 512B blocks allocated
            st->st_blocks = RT_ALIGN(st->st_size, st->st_blksize) / 512;

            ext4_put_inode_ref(mp, &inode_ref);
        }
        else
        {
            ret = ENOENT;
        }

        rt_free(stat_path);
    }

    return -ret;
}

int dfs_ext_setattr(struct dfs_dentry *dentry, struct dfs_attr *attr)
{
    int ret = 0;
    char *fn = NULL;

    fn = dfs_dentry_full_path(dentry);
    if (fn)
    {
        if (attr->ia_valid & ATTR_MODE_SET)
        {
            ret = ext4_mode_set(fn, attr->st_mode);
        }
        if (attr->ia_valid & ATTR_ATIME_SET)
        {
            ret = ext4_atime_set(fn, attr->ia_atime.tv_sec);
        }
        if (attr->ia_valid & ATTR_MTIME_SET)
        {
            ret = ext4_mtime_set(fn, attr->ia_mtime.tv_sec);
        }
        if (attr->ia_valid & ATTR_UID_SET)
        {
            uint32_t unuse = 0, gid = 0;
            ext4_owner_get(fn, &unuse, &gid);
            ret = ext4_owner_set(fn, attr->st_uid, gid);
        }
        if (attr->ia_valid & ATTR_GID_SET)
        {
            uint32_t unuse = 0, uid = 0;
            ext4_owner_get(fn, &uid, &unuse);
            ret = ext4_owner_set(fn, uid, attr->st_gid);
        }
        ext4_vnode_update_info(dentry->vnode);
        rt_free(fn);
    }
    else
    {
        ret = ENOENT;
    }

    return ret;
}

static int dfs_ext_getdents(struct dfs_file *file, struct dirent *dirp, rt_uint32_t count)
{
    int index;
    struct dirent *d;
    struct dfs_ext4_file *ext_file;
    const ext4_direntry *rentry;

    /* make integer count */
    count = (count / sizeof(struct dirent)) * sizeof(struct dirent);
    if (count == 0 || file->data == RT_NULL)
    {
        return -RT_EINVAL;
    }

    index = 0;
    ext_file = (struct dfs_ext4_file *)file->data;
    while (1)
    {
        d = dirp + index;

        rentry = ext4_dir_entry_next(&(ext_file->entry.dir));
        if (rentry != NULL)
        {
            strncpy(d->d_name, (char *)rentry->name, DIRENT_NAME_MAX);
            if (rentry->inode_type == EXT4_DE_DIR)
            {
                d->d_type = DT_DIR;
            }
            else if (rentry->inode_type == EXT4_DE_SYMLINK)
            {
                d->d_type = DT_SYMLINK;
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

    file->fpos += index * sizeof(struct dirent);

    return index * sizeof(struct dirent);
}

static int dfs_ext_rename(struct dfs_dentry *old_dentry, struct dfs_dentry *new_dentry)
{
    int r = EPERM;
    char *oldpath, *newpath;

    oldpath = dfs_dentry_full_path(old_dentry);
    newpath = dfs_dentry_full_path(new_dentry);

    if (oldpath && newpath)
    {
        r = ext4_frename(oldpath, newpath);
    }

    rt_free(oldpath);
    rt_free(newpath);

    return -r;
}

static int dfs_ext_truncate(struct dfs_file *file, off_t offset)
{
    struct dfs_ext4_file *ext_file = (struct dfs_ext4_file *)file->data;

    if (ext_file)
    {
        ext4_ftruncate(&(ext_file->entry.file), offset);
    }

    if (file->vnode->size < offset)
    {
        file->vnode->size = offset;
    }

    return 0;
}

static int dfs_ext_ioctl(struct dfs_file *file, int cmd, void *args)
{
    int ret = RT_EOK;

    switch (cmd)
    {
    case RT_FIOFTRUNCATE:
    {
        off_t offset = (off_t)(size_t)(args);
        ret = dfs_ext_truncate(file, offset);
    }
    break;

    case F_GETLK:
    case F_SETLK:
        ret = RT_EOK;
        break;

    default:
        ret = -RT_EIO;
        break;
    }

    return ret;
}

#ifdef RT_USING_PAGECACHE
static ssize_t dfs_ext_page_read(struct dfs_file *file, struct dfs_page *page)
{
    ssize_t ret = -EINVAL;

    if (page->page)
    {
        uint32_t flags;
        off_t fpos = page->fpos;

        if (file && file->data)
        {
            struct dfs_ext4_file *ext_file = (struct dfs_ext4_file *)file->data;

            rt_mutex_take(&file->vnode->lock, RT_WAITING_FOREVER);
            flags = ext_file->entry.file.flags;
            ext_file->entry.file.flags = O_RDWR;
            ret = dfs_ext_read(file, page->page, page->size, &fpos);
            ext_file->entry.file.flags = flags;
            rt_mutex_release(&file->vnode->lock);
        }
    }

    return ret;
}

static ssize_t dfs_ext_page_write(struct dfs_page *page)
{
    int r;
    size_t byteswritten = 0;
    struct dfs_ext4_file *ext_file;

    if (page && page->aspace->vnode && page->aspace->vnode->data)
    {
        ext_file = (struct dfs_ext4_file *)page->aspace->vnode->data;
        rt_mutex_take(&page->aspace->vnode->lock, RT_WAITING_FOREVER);
        ext4_fseek(&(ext_file->entry.file), (int64_t)page->fpos, SEEK_SET);
        r = ext4_fwrite(&(ext_file->entry.file), page->page, page->len, &byteswritten);
        if (r != 0)
        {
            byteswritten = 0;
        }
        rt_mutex_release(&page->aspace->vnode->lock);
    }

    return byteswritten;
}
#endif

static const struct dfs_file_ops _extfs_fops =
{
    .open       = dfs_ext_open,
    .close      = dfs_ext_close,
    .ioctl      = dfs_ext_ioctl,
    .read       = dfs_ext_read,
    .write      = dfs_ext_write,
    .flush      = dfs_ext_flush,
    .lseek      = dfs_ext_lseek,
    .truncate   = dfs_ext_truncate,
    .getdents   = dfs_ext_getdents,
};

static const struct dfs_filesystem_ops _extfs_ops =
{
    .name           = "ext",
    .flags          = FS_NEED_DEVICE,
    .default_fops   = &_extfs_fops,

    .mount  = dfs_ext_mount,
    .umount = dfs_ext_unmount,
    .mkfs   = dfs_ext_mkfs,
    .statfs = dfs_ext_statfs, /* statfs */

    .readlink   = dfs_ext_readlink,
    .link       = dfs_ext_link,
    .unlink     = dfs_ext_unlink,
    .symlink    = dfs_ext_symlink,
    .stat       = dfs_ext_stat,
    .setattr    = dfs_ext_setattr,
    .rename     = dfs_ext_rename,

    .lookup         = dfs_ext_lookup,
    .create_vnode   = dfs_ext_create_vnode,
    .free_vnode     = dfs_ext_free_vnode,
};

static struct dfs_filesystem_type _extfs =
{
    .fs_ops = &_extfs_ops,
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
    dfs_register(&_extfs);
    return 0;
}
INIT_COMPONENT_EXPORT(dfs_ext_init);
