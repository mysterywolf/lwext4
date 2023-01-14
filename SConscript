from building import *

cwd = GetCurrentDir()

objs = Split('''
src/ext4.c
src/ext4_balloc.c
src/ext4_bcache.c
src/ext4_bitmap.c
src/ext4_blockdev.c
src/ext4_block_group.c
src/ext4_crc32.c
src/ext4_debug.c
src/ext4_dir.c
src/ext4_dir_idx.c
src/ext4_extent.c
src/ext4_fs.c
src/ext4_hash.c
src/ext4_ialloc.c
src/ext4_inode.c
src/ext4_journal.c
src/ext4_mkfs.c
src/ext4_mp.c
src/ext4_super.c
src/ext4_trans.c
src/ext4_xattr.c
ports/rtthread/dfs_ext.c
ports/rtthread/dfs_ext_blockdev.c
''')

CPPPATH = [cwd + '/include', cwd + '/ports/rtthread']
CPPDEFINES = ['CONFIG_USE_DEFAULT_CFG', 'CONFIG_HAVE_OWN_OFLAGS=0']

LOCAL_CCFLAGS = ''

group = DefineGroup('Filesystem', objs,
            depend = ['RT_USING_DFS', 'RT_USING_DFS_LWEXT4'],
            CPPPATH = CPPPATH,
            CPPDEFINES = CPPDEFINES,
            LOCAL_CCFLAGS = LOCAL_CCFLAGS)

Return('group')
