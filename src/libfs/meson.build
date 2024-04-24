libfs_h = include_directories(
    '..', '../..',
)
libfs = static_library('fs',
    'base.cpp',
    'ext4/ext4.cpp',

    dependencies : deps,
    include_directories : libfs_h,
    link_with : libdrakvuf
)
