#ifndef __BLK_DEVICE_H__
#define __BLK_DEVICE_H__

#include <ext4_blockdev.h>

int get_partition(int part_id, struct ext4_blockdev *part);
void lwext4_init(rt_device_t mbr_device);

#endif

