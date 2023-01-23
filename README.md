# RT-Thread下的EXT4文件系统

这是一份RT-Thread下的EXT4文件系统实现，基于lwext4，针对RT-Thread的最新版本进行适配，后续也会适配到RT-Thread重构后的设备文件系统（DFS）上。

## lwext4文件系统

lwext4文件系统是一份针对MCU的ext2/3/4的文件系统实现，大多数代码源自 [helenos](http://helenos.org)，原许可协议是BSD许可协议。

lwext4中为了加入更多的扩展，添加了这两份文件，这两份文件是GPLv2许可协议。
* ext4_xattr.c
* ext4_extents.c

因为这两个文件GPLv2许可协议的缘故，会造成整体lwext4的文件污染。

原来的功能特性包括：

* filetypes: regular, directories, softlinks
* support for hardlinks
* multiple blocksize supported: 1KB, 2KB, 4KB ... 64KB
* little/big endian architectures supported
* multiple configurations (ext2/ext3/ext4)
* only C standard library dependency
* various CPU architectures supported (x86/64, cortex-mX, msp430 ...)
* small memory footprint
* flexible configurations

[原来的README.md文件](README_org.md)

## 移植到RT-Thread的修改

* lwext4中的分区表相关功能都未启用；
* lwext4中本身的块设备功能移除，都由dfs_ext_blockdev来实现；
* mkfs格式化文件系统都不会涉及到分区表的操作；
