libinjector_h = include_directories(
    '..', '../..',
    'linux', 'linux/methods',
    'win', 'win/methods'
)
libinjector = static_library('injector',
    'injector.c',
    'debug_helpers.c',
    'injector_stack.c',
    'injector_utils.c',
    'win/method_helpers.c',
    'win/win_functions.c',
    'win/win_injector.c',
    'win/win_utils.c',
    'win/methods/win_createproc.c',
    'win/methods/win_exitthread.c',
    'win/methods/win_read_file.c',
    'win/methods/win_shellcode.c',
    'win/methods/win_shellexec.c',
    'win/methods/win_terminate.c',
    'win/methods/win_write_file.c',
    'linux/linux_injector.c',
    'linux/linux_syscalls.c',
    'linux/linux_utils.c',
    'linux/methods/linux_execve.c',
    'linux/methods/linux_read_file.c',
    'linux/methods/linux_shellcode.c',
    'linux/methods/linux_write_file.c',

    dependencies : deps,
    include_directories : libinjector_h,
    link_with : libdrakvuf
)
