project('drakvuf', 'c', 'cpp', version : '1.0')
add_project_arguments('-DPACKAGE_NAME="drakvuf"', language : 'c')
add_project_arguments('-DPACKAGE_VERSION="1.0"', language : 'c')

subdir('mesontest')

glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
jsonc = dependency('json-c')
libxc = dependency('xencontrol')
libxl = dependency('xenlight')
libxfm = dependency('xenforeignmemory')
libxtl = dependency('xentoollog')

incdir = include_directories('src')

libdrakvuf = static_library('libdrakvuf',
    'src/libdrakvuf/drakvuf.c',
    'src/libdrakvuf/vmi.c',
    'src/libdrakvuf/helper.c',
    'src/libdrakvuf/json-profile.c',
    'src/libdrakvuf/json-util.c',
    'src/libdrakvuf/linux-exports.c',
    'src/libdrakvuf/linux-processes.c',
    'src/libdrakvuf/linux.c',
    'src/libdrakvuf/os.c',
    'src/libdrakvuf/win-exports.c',
    'src/libdrakvuf/win-files.c',
    'src/libdrakvuf/win-handles.c',
    'src/libdrakvuf/win-processes.c',
    'src/libdrakvuf/win-registry.c',
    'src/libdrakvuf/win.c',

    dependencies : [glib, libvmi, jsonc]
)

xen_helper = static_library('xen_helper',
    'src/xen_helper/xen_helper.c',
    dependencies : [glib, libxc, libxl, libxfm, libxtl]
)

libinjector_h = include_directories(
    'src/libinjector',
    'src/libinjector/linux', 'src/libinjector/linux/methods',
    'src/libinjector/win', 'src/libinjector/win/methods'
)
libinjector = static_library('libinjector',
    'src/libinjector/injector.c',
    'src/libinjector/debug_helpers.c',
    'src/libinjector/injector_stack.c',
    'src/libinjector/injector_utils.c',
    'src/libinjector/win/method_helpers.c',
    'src/libinjector/win/win_functions.c',
    'src/libinjector/win/win_injector.c',
    'src/libinjector/win/win_utils.c',
    'src/libinjector/win/methods/win_createproc.c',
    'src/libinjector/win/methods/win_read_file.c',
    'src/libinjector/win/methods/win_shellcode.c',
    'src/libinjector/win/methods/win_shellexec.c',
    'src/libinjector/win/methods/win_terminate.c',
    'src/libinjector/win/methods/win_write_file.c',
    'src/libinjector/linux/linux_injector.c',
    'src/libinjector/linux/linux_syscalls.c',
    'src/libinjector/linux/linux_utils.c',
    'src/libinjector/linux/methods/linux_execve.c',
    'src/libinjector/linux/methods/linux_read_file.c',
    'src/libinjector/linux/methods/linux_shellcode.c',
    'src/libinjector/linux/methods/linux_write_file.c',

    dependencies : [glib, libvmi],
    include_directories : [incdir, libinjector_h],
    link_with : [libdrakvuf, xen_helper]
)
executable('injector',
    'src/injector.c',

    dependencies : [glib, libvmi],
    include_directories : incdir,
    link_with : [libdrakvuf, libinjector]
)

if get_option('xtf').enabled()
    executable('xtf',
           'src/xtf.c',

           dependencies : [glib, libvmi],
           include_directories : incdir,
           link_with : [libdrakvuf, xen_helper]
    )
endif
