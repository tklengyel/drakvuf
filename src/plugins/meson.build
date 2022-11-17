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

if get_option('plugin-delaymon')
    plugin_sources += 'delaymon/delaymon.cpp'

    config_h.set('ENABLE_PLUGIN_DELAYMON', 1)
endif

if get_option('plugin-dkommon')
    plugin_sources += 'dkommon/dkommon.cpp'

    config_h.set('ENABLE_PLUGIN_DKOMMON', 1)
endif

if get_option('plugin-envmon')
    plugin_sources += 'envmon/envmon.cpp'

    config_h.set('ENABLE_PLUGIN_ENVMON', 1)
endif

if get_option('plugin-exmon')
    plugin_sources += 'exmon/exmon.cpp'

    config_h.set('ENABLE_PLUGIN_EXMON', 1)
endif

if get_option('plugin-exploitmon')
    plugin_sources += 'exploitmon/exploitmon.cpp'

    config_h.set('ENABLE_PLUGIN_EXPLOITMON', 1)
endif

if get_option('plugin-filedelete')
    plugin_sources += 'filedelete/filedelete.cpp'
    plugin_sources += 'filedelete/filedelete2_helpers.cpp'

    config_h.set('ENABLE_PLUGIN_FILEDELETE', 1)
endif

if get_option('plugin-fileextractor')
    plugin_sources += 'fileextractor/fileextractor.cpp'

    config_h.set('ENABLE_PLUGIN_FILEEXTRACTOR', 1)
endif

if get_option('plugin-filetracer')
    plugin_sources += 'filetracer/filetracer.cpp'
    plugin_sources += 'filetracer/linux.cpp'
    plugin_sources += 'filetracer/win.cpp'
    plugin_sources += 'filetracer/win_acl.cpp'

    config_h.set('ENABLE_PLUGIN_FILETRACER', 1)
endif

if get_option('plugin-hidsim')
    plugin_sources += 'hidsim/hidsim.cpp'
    plugin_sources += 'hidsim/qmp/qmp_connection.cpp'
    plugin_sources += 'hidsim/hid_injection.cpp'
    plugin_sources += 'hidsim/gui/vmi_win_gui_parser.cpp'
    plugin_sources += 'hidsim/gui/vmi_win_gui_utils.cpp'
    plugin_sources += 'hidsim/gui/vmi_win_gui_offsets.cpp'
    plugin_sources += 'hidsim/gui/vmi_win_gui_atoms.cpp'
    plugin_sources += 'hidsim/gui_monitor.cpp'

    pthread = dependency('threads')
    deps += pthread

    config_h.set('ENABLE_PLUGIN_HIDSIM', 1)
endif

if get_option('plugin-librarymon')
    plugin_sources += 'librarymon/librarymon.cpp'

    config_h.set('ENABLE_PLUGIN_LIBRARYMON', 1)
endif

if get_option('plugin-memdump')
    plugin_sources += 'memdump/memdump.cpp'
    plugin_sources += 'memdump/stack_util.cpp'
    plugin_sources += 'memdump/userhook.cpp'

    config_h.set('ENABLE_PLUGIN_MEMDUMP', 1)
endif

if get_option('plugin-objmon')
    plugin_sources += 'objmon/objmon.cpp'

    config_h.set('ENABLE_PLUGIN_OBJMON', 1)
endif

if get_option('plugin-rootkitmon')
    plugin_sources += 'rootkitmon/rootkitmon.cpp'

    config_h.set('ENABLE_PLUGIN_ROOTKITMON', 1)
endif

if get_option('plugin-spraymon')
    plugin_sources += 'spraymon/spraymon.cpp'

    config_h.set('ENABLE_PLUGIN_SPRAYMON', 1)
endif

if get_option('plugin-hidevm')
    plugin_sources += 'hidevm/hidevm.cpp'

    config_h.set('ENABLE_PLUGIN_HIDEVM', 1)
endif

if get_option('plugin-ptracemon')
    plugin_sources += 'ptracemon/ptracemon.cpp'

    config_h.set('ENABLE_PLUGIN_PTRACEMON', 1)
endif

if get_option('plugin-ebpfmon')
    plugin_sources += 'ebpfmon/ebpfmon.cpp'

    config_h.set('ENABLE_PLUGIN_EBPFMON', 1)
endif

if get_option('plugin-memaccessmon')
    plugin_sources += 'memaccessmon/memaccessmon.cpp'

    config_h.set('ENABLE_PLUGIN_EBPFMON', 1)
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
    'delaymon': get_option('plugin-delaymon'),
    'dkommon': get_option('plugin-dkommon'),
    'envmon': get_option('plugin-envmon'),
    'exmon': get_option('plugin-exmon'),
    'exploitmon': get_option('plugin-exploitmon'),
    'fileextractor': get_option('plugin-fileextractor'),
    'filetracer': get_option('plugin-filetracer'),
    'hidsim': get_option('plugin-hidsim'),
    'librarymon': get_option('plugin-librarymon'),
    'memdump': get_option('plugin-memdump'),
    'objmon': get_option('plugin-objmon'),
    'rootkitmon': get_option('plugin-rootkitmon'),
    'spraymon': get_option('plugin-spraymon'),
    'hidevm': get_option('plugin-hidevm'),
    'ptracemon': get_option('plugin-ptracemon'),
    'ebpfmon' : get_option('plugin-ebpfmon'),
    'memaccessmon' : get_option('plugin-memaccessmon'),
}, section: 'Plugins (-Dplugin-<x>)')

summary({
    'filedelete': get_option('plugin-filedelete'),
}, section: 'Deprecated plugins')

#################

drakvuf_plugins = static_library('drakvuf_plugins',
    sources : plugin_sources,
    include_directories : incdir,
    dependencies : deps,
    link_with : [libdrakvuf, libhook, libusermode],
    link_args : hardened_link_args
)
