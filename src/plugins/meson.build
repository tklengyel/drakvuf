incdir = include_directories('..', '../..')

plugin_sources = [
    'plugins.cpp',
    'plugins_ex.cpp',
    'plugin_utils.cpp',
    'output_format/ostream.cpp'
]

if get_option('plugin-syscalls')
    plugin_sources += 'syscalls/syscalls.cpp'
    plugin_sources += 'syscalls/win.cpp'
    plugin_sources += 'syscalls/linux.cpp'

    config_h.set('ENABLE_PLUGIN_SYSCALLS', 1)
endif

if get_option('plugin-poolmon')
    plugin_sources += 'poolmon/poolmon.cpp'

    config_h.set('ENABLE_PLUGIN_POOLMON', 1)
endif

if get_option('plugin-apimon')
    plugin_sources += 'apimon/apimon.cpp'
    plugin_sources += 'apimon/crypto.cpp'

    config_h.set('ENABLE_PLUGIN_APIMON', 1)
endif

if get_option('plugin-bsodmon')
    plugin_sources += 'bsodmon/bsodmon.cpp'
    plugin_sources += 'bsodmon/bugcheck.cpp'

    config_h.set('ENABLE_PLUGIN_BSODMON', 1)
endif

if get_option('plugin-callbackmon')
    plugin_sources += 'callbackmon/callbackmon.cpp'

    config_h.set('ENABLE_PLUGIN_CALLBACKMON', 1)
endif

if get_option('plugin-clipboardmon')
    plugin_sources += 'clipboardmon/clipboardmon.cpp'

    config_h.set('ENABLE_PLUGIN_CLIPBOARDMON', 1)
endif

if get_option('plugin-codemon')
    plugin_sources += 'codemon/codemon.cpp'

    config_h.set('ENABLE_PLUGIN_CODEMON', 1)
endif

if get_option('plugin-cpuidmon')
    plugin_sources += 'cpuidmon/cpuidmon.cpp'

    config_h.set('ENABLE_PLUGIN_CPUIDMON', 1)
endif

if get_option('plugin-crashmon')
    plugin_sources += 'crashmon/crashmon.cpp'

    config_h.set('ENABLE_PLUGIN_CRASHMON', 1)
endif

if get_option('plugin-debugmon')
    plugin_sources += 'debugmon/debugmon.cpp'

    config_h.set('ENABLE_PLUGIN_DEBUGMON', 1)
endif

summary({
    'syscalls': get_option('plugin-syscalls'),
    'poolmon': get_option('plugin-poolmon'),
    'apimon': get_option('plugin-apimon'),
    'bsodmon': get_option('plugin-bsodmon'),
    'callbackmon': get_option('plugin-callbackmon'),
    'clipboardmon': get_option('plugin-clipboardmon'),
    'codemon': get_option('plugin-codemon'),
    'cpuidmon': get_option('plugin-cpuidmon'),
    'crashmon': get_option('plugin-crashmon'),
    'debugmon': get_option('plugin-debugmon'),
}, section: 'Plugins (-Dplugin-<x>)')

#################

drakvuf_plugins = static_library('drakvuf_plugins',
    sources : plugin_sources,

    include_directories : incdir,
    dependencies : deps,
    link_with : [libdrakvuf, libhook, libusermode],
    link_args : hardened_link_args
)
