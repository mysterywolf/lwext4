/** @addtogroup lwext4
 * @{
 */
/**
 * @file  ext4_mp.h
 * @brief mount point handle functions
 */

#ifndef EXT4_MP_H_
#define EXT4_MP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ext4_config.h>
#include <ext4_types.h>
#include <ext4_fs.h>
#include <ext4_journal.h>

#include <stdint.h>

/**@brief   Mount point OS dependent lock*/
#define EXT4_MP_LOCK(_m)                                           \
    do {                                                           \
        if ((_m)->os_locks)                                        \
            (_m)->os_locks->lock();                                \
    } while (0)

/**@brief   Mount point OS dependent unlock*/
#define EXT4_MP_UNLOCK(_m)                                         \
    do {                                                           \
        if ((_m)->os_locks)                                        \
            (_m)->os_locks->unlock();                              \
    } while (0)

/**@brief   Mount point descriptor.*/
struct ext4_mountpoint {

    /**@brief   Mount done flag.*/
    bool mounted;

    /**@brief   Mount point name (@ref ext4_mount)*/
    char name[CONFIG_EXT4_MAX_MP_NAME + 1];

    /**@brief   OS dependent lock/unlock functions.*/
    const struct ext4_lock *os_locks;

    /**@brief   Ext4 filesystem internals.*/
    struct ext4_fs fs;

    /**@brief   JBD fs.*/
    struct jbd_fs jbd_fs;

    /**@brief   Journal.*/
    struct jbd_journal jbd_journal;

    /**@brief   Block cache.*/
    struct ext4_bcache bc;
};

#ifdef __cplusplus
}
#endif

#endif /* EXT4_MP_H_ */
