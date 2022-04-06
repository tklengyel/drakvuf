incdir = include_directories('..', '../..')

plugin_sources = [
    'plugins.cpp',
    'plugins_ex.cpp',
    'plugin_utils.cpp',
    'output_format/ostream.cpp'
]

if get_option('plugin-syscalls').enabled()
    plugin_sources += 'syscalls/syscalls.cpp'
    plugin_sources += 'syscalls/win.cpp'
    plugin_sources += 'syscalls/linux.cpp'

    config_h.set('ENABLE_PLUGIN_SYSCALLS', 1)
endif

if get_option('plugin-poolmon').enabled()
    plugin_sources += 'poolmon/poolmon.cpp'

    config_h.set('ENABLE_PLUGIN_POOLMON', 1)
endif

if get_option('plugin-apimon').enabled()
    plugin_sources += 'apimon/apimon.cpp'
    plugin_sources += 'apimon/crypto.cpp'

    config_h.set('ENABLE_PLUGIN_APIMON', 1)
endif

drakvuf_plugins = static_library('drakvuf_plugins',
    sources : plugin_sources,

    include_directories : incdir,
    dependencies : deps,
    link_with : [libdrakvuf, xen_helper, libhook, libusermode],
    link_args : hardened_link_args
)

summary({
    'Syscalls': get_option('plugin-syscalls').enabled(),
    'Poolmon': get_option('plugin-poolmon').enabled(),
    'APImon': get_option('plugin-apimon').enabled(),
        }, section: 'Plugins')
