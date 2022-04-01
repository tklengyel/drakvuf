libusermode_h = include_directories(
    '..', '../..'
)
libusermode = static_library('usermode',
    'userhook.cpp',
    'running.cpp',
    'printers/printers.cpp',

    dependencies : [glib, libvmi],
    include_directories : libusermode_h,
    link_with : libdrakvuf
)
