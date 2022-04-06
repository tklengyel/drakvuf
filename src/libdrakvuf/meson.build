incdir = include_directories('../..')

libdrakvuf = static_library('drakvuf',
    'drakvuf.c',
    'vmi.c',
    'helper.c',
    'json-profile.c',
    'json-util.c',
    'linux-exports.c',
    'linux-processes.c',
    'linux.c',
    'os.c',
    'win-exports.c',
    'win-files.c',
    'win-handles.c',
    'win-processes.c',
    'win-registry.c',
    'win.c',

    include_directories : incdir,
    dependencies : [glib, libvmi, jsonc],
    link_with : xen_helper,
    link_args : hardened_link_args
)
