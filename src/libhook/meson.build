libhook_h = include_directories(
    '..', '../..',
)
libhook = static_library('hook',
    'hooks/base.cpp',
    'hooks/manual.cpp',
    'hooks/syscall.cpp',
    'hooks/return.cpp',
    'hooks/cr3.cpp',
    'hooks/cpuid.cpp',

    dependencies : [glib, libvmi],
    include_directories : libhook_h,
    link_with : libdrakvuf
)
