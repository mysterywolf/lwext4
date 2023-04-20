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

#ifdef PKG_USING_DLOG
#include <dlog.h>
#else
#define DLOG(...)
#endif

struct dfs_ext4_file
{
    uint32_t type;  /* EXT4_DE_DIR or EXT4_DE_REG_FILE */
    union {
        ext4_file file;
        ext4_dir dir;
    } entry;
};

struct dfs_ext4_vnode
{
    struct ext4_mountpoint *mp;
    struct ext4_inode_ref inode_ref;
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
    return ;
}

static void ext4_unlock(void)
{
    rt_mutex_release(ext4_mutex);
    return ;
}

/* update vnode information */
rt_inline int ext4_vnode_update_info(struct dfs_vnode *vnode)
{
    struct dfs_ext4_vnode *ext_vnode;

    if (vnode && vnode->data)
    {
        ext_vnode = (struct dfs_ext4_vnode *)vnode->data;
        if (ext_vnode)
        {
            vnode->mode = ext4_inode_get_mode(&ext_vnode->mp->fs.sb, ext_vnode->inode_ref.inode);
            vnode->uid = ext4_inode_get_uid(ext_vnode->inode_ref.inode);
            vnode->gid = ext4_inode_get_gid(ext_vnode->inode_ref.inode);
            vnode->atime.tv_sec = ext4_inode_get_access_time(ext_vnode->inode_ref.inode);
            vnode->mtime.tv_sec = ext4_inode_get_modif_time(ext_vnode->inode_ref.inode);
            vnode->ctime.tv_sec = ext4_inode_get_change_inode_time(ext_vnode->inode_ref.inode);
        }
    }

    return 0;
}

/* file system ops */

static struct dfs_vnode* dfs_ext_lookup(struct dfs_dentry *dentry)
{
    char *fn = RT_NULL;
    struct dfs_vnode *vnode = RT_NULL;
    struct dfs_ext4_vnode *ext_vnode = RT_NULL;

    ext_vnode = (struct dfs_ext4_vnode *) rt_calloc (1, sizeof(struct dfs_ext4_vnode));
    if (ext_vnode)
    {
        fn = dfs_dentry_full_path(dentry);
        if (fn)
        {
            DLOG(msg, "ext", "vnode", DLOG_MSG, "dfs_vnode_create()");
            vnode = dfs_vnode_create();
            if (vnode)
            {
                ext_vnode->mp = ext4_get_inode_ref(fn, &(ext_vnode->inode_ref));
                if (ext_vnode->mp)
                {
                    /* found entry */
                    int type = ext4_inode_type(&(ext_vnode->mp->fs.sb), ext_vnode->inode_ref.inode);
                    switch (type)
                    {
                    case EXT4_INODE_MODE_FILE:
                        vnode->type = FT_REGULAR;
                        vnode->size = ext4_inode_get_size(&(ext_vnode->mp->fs.sb), ext_vnode->inode_ref.inode);
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
                    vnode->data = (void*) ext_vnode;

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
            rt_free(ext_vnode);
        }
    }

    return vnode;
}

static struct dfs_vnode* dfs_ext_create_vnode(struct dfs_dentry *dentry, int type, mode_t mode)
{
    int ret = 0;
    char *fn = NULL;
    struct dfs_vnode *vnode = RT_NULL;
    struct dfs_ext4_vnode *ext_vnode = RT_NULL;

    vnode = dfs_vnode_create();
    if (vnode)
    {
        fn = dfs_dentry_full_path(dentry);
        if (fn)
        {
            ext_vnode = (struct dfs_ext4_vnode *) rt_malloc (sizeof(struct dfs_ext4_vnode));
            if (ext_vnode)
            {
                if (type == FT_DIRECTORY)
                {
                    /* create dir */
                    ret = ext4_dir_mk(fn);
                    if (ret == EOK)
                    {
                        ext4_mode_set(fn, mode);
                        ext_vnode->mp = ext4_get_inode_ref(fn, &(ext_vnode->inode_ref));
                        if (ext_vnode->mp)
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
                    ret = ext4_fopen2(&file, fn, O_CREAT);
                    if (ret == EOK)
                    {
                        ext4_fclose(&file);

                        ext4_mode_set(fn, mode);
                        ext_vnode->mp = ext4_get_inode_ref(fn, &(ext_vnode->inode_ref));
                        if (ext_vnode->mp)
                        {
                            vnode->type = FT_REGULAR;
                            vnode->size = ext4_inode_get_size(&(ext_vnode->mp->fs.sb), ext_vnode->inode_ref.inode);
                        }
                    }
                }

                if (ret != EOK)
                {
                    rt_free(ext_vnode);
                    ext_vnode = NULL;

                    dfs_vnode_destroy(vnode);
                    vnode = NULL;
                }
                else
                {
                    DLOG(msg, "ext", "mnt", DLOG_MSG, "dfs_mnt_ref(dentry->mnt, name=%s)", dentry->mnt->fs_ops->name);
                    vnode->mnt = dentry->mnt;
                    vnode->data = ext_vnode;
                    vnode->mode = mode;
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

static int dfs_ext_free_vnode(struct dfs_vnode* vnode)
{
    if (vnode)
    {
        struct dfs_ext4_vnode *ext_vnode;

        if (vnode->data)
        {
            ext_vnode = (struct dfs_ext4_vnode *)vnode->data;
            if (ext_vnode)
            {
                ext4_put_inode_ref(ext_vnode->mp, &(ext_vnode->inode_ref));
                rt_free(ext_vnode);
            }

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
        mnt->data = (void*) dbd;
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

static int dfs_ext_read(struct dfs_file *fd, void *buf, size_t count, off_t *pos)
{
    int r;
    size_t bytesread = 0;
    struct dfs_ext4_file *ext_file;

    if (fd && fd->data)
    {
        ext_file = (struct dfs_ext4_file *) fd->data;

        r = ext4_fread(&ext_file->entry.file, buf, count, &bytesread);
        if (r != 0)
        {
            bytesread = 0;
        }
        *pos = ext4_fsize(&(ext_file->entry.file));
    }

    return bytesread;
}

static int dfs_ext_write(struct dfs_file *fd, const void *buf, size_t count, off_t *pos)
{
    int r;
    size_t byteswritten = 0;
    struct dfs_ext4_file *ext_file;

    if (fd && fd->data)
    {
        ext_file = (struct dfs_ext4_file *) fd->data;

        r = ext4_fwrite(&(ext_file->entry.file), buf, count, &byteswritten);
        if (r != 0)
        {
            byteswritten = 0;
        }

        fd->vnode->size = ext4_fsize(&(ext_file->entry.file));
        *pos = fd->vnode->size;
    }

    return byteswritten;
}

static int dfs_ext_flush(struct dfs_file *fd)
{
    char *fn = RT_NULL;
    int error = RT_EOK;

    if (fd && fd->dentry)
    {
        fn = dfs_dentry_full_path(fd->dentry);
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

static int dfs_ext_lseek(struct dfs_file *fd, off_t offset, int whence)
{
    int r = EPERM;
    struct dfs_ext4_file *ext_file;

    if (fd && fd->data)
    {
        ext_file = (struct dfs_ext4_file *)fd->data;

        if (ext_file->type == FT_DIRECTORY)
        {
            if (offset == 0)
            {
                ext4_dir_entry_rewind(&(ext_file->entry.dir));
                return 0;
            }
        }
        else
        {
            r = ext4_fseek(&(ext_file->entry.file), (int64_t)offset, whence);
            if (r == RT_EOK)
            {
                return ext_file->entry.file.fpos;
            }
        }
    }

    return -r;
}

static int dfs_ext_close(struct dfs_file *file)
{
    int ret = 0;
    struct dfs_ext4_file *ext_file = RT_NULL;

    if (file)
    {
        ext_file = (struct dfs_ext4_file *) file->data;
        if (ext_file)
        {
            if (ext_file->type == FT_DIRECTORY)
            {
                ret = ext4_dir_close(&ext_file->entry.dir);
            }
            else if (ext_file->type == FT_REGULAR)
            {
                ret = ext4_fclose(&ext_file->entry.file);
            }

            if (ret == EOK)
            {
                rt_free(ext_file);
                file->data = NULL;
            }
        }
    }

    return -ret;
}

static int dfs_ext_open(struct dfs_file *file)
{
    int ret = EOK;
    struct dfs_ext4_vnode *ext_vnode = RT_NULL;
    struct dfs_ext4_file *ext_file = RT_NULL;

    if (file && file->vnode)
    {
        ext_vnode = (struct dfs_ext4_vnode *)file->vnode->data;
        if (ext_vnode)
        {
            ext_file = (struct dfs_ext4_file *) rt_malloc(sizeof(struct dfs_ext4_file));
            if (ext_file)
            {
                char *fn = NULL;

                ext_file->type = file->vnode->type;

                fn = dfs_dentry_full_path(file->dentry);
                if (fn)
                {
                    if (file->vnode->type == FT_DIRECTORY)
                    {
                        /* open dir */
                        ret = ext4_dir_open(&ext_file->entry.dir, fn);
                        if (ret == EOK)
                        {
                            file->fpos = 0;
                        }
                    }
                    else
                    {
                        /* open regular file */
                        ret = ext4_fopen2(&ext_file->entry.file, fn, file->flags);
                        if (ret == EOK)
                        {
                            file->fpos = ext_file->entry.file.fpos;
                        }
                    }

                    if (ret == EOK)
                    {
                        file->data = ext_file;
                    }

                    rt_free(fn);
                }
                else
                {
                    rt_free(ext_file);
                    ext_file = NULL;
                }
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
        fn = (char*) linkpath;
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
            (void) ext4_dir_close(&(file.entry.dir));
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
            st->st_size = ext4_inode_get_size(&mp->fs.sb, inode_ref.inode);
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
	    ret = ext4_mode_set(fn, attr->st_mode);
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
    ext_file = (struct dfs_ext4_file*)file->data;
    while (1)
    {
        d = dirp + index;

        rentry = ext4_dir_entry_next(&(ext_file->entry.dir));
        if (rentry != NULL)
        {
            strncpy(d->d_name, (char *)rentry->name, DFS_PATH_MAX);
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
    return 0;
}

static int dfs_ext_ioctl(struct dfs_file *fd, int cmd, void *args)
{
    int ret = RT_EOK;

    switch (cmd)
    {
    case RT_FIOFTRUNCATE:
        {
            off_t offset = (off_t)(size_t)(args);
            ret = dfs_ext_truncate(fd, offset);
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

static const struct dfs_file_ops _extfs_fops =
{
    .open  = dfs_ext_open,
    .close = dfs_ext_close,
    .ioctl = dfs_ext_ioctl,
    .read  = dfs_ext_read,
    .write = dfs_ext_write,
    .flush = dfs_ext_flush,
    .lseek = dfs_ext_lseek,
    .truncate = dfs_ext_truncate,
    .getdents = dfs_ext_getdents,
};

static const struct dfs_filesystem_ops _extfs_ops =
{
    .name   = "ext",
    .flags  = FS_NEED_DEVICE,
    .default_fops = &_extfs_fops,

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

    .lookup     = dfs_ext_lookup,
    .create_vnode = dfs_ext_create_vnode,
    .free_vnode   = dfs_ext_free_vnode,
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
