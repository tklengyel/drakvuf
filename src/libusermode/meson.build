libusermode_h = include_directories(
    '..', '../..'
)
libusermode = static_library('usermode',
    'userhook.cpp',
    'userhook_pf.cpp',
    'userhook_inject.cpp',
    'running.cpp',
    'utils.cpp',
    'printers/printers.cpp',
    'printers/utils.cpp',

    dependencies : deps,
    include_directories : libusermode_h,
    link_with : libdrakvuf
)

if check.found()
    userhook_check = executable('userhook_check',
        sources : 'check.cpp',
        include_directories : libusermode_h,
        dependencies : [deps, check],
        link_with : [libdrakvuf, libusermode]
    )
    test('userhook_check', userhook_check)

    if meson.version().version_compare('>=1.1.0')
        utils_o = libusermode.extract_objects('printers/utils.cpp')
        utils_dep = declare_dependency(objects: utils_o)
        libusermode_printers_check = executable('libusermode_printers_check',
            sources : 'printers/check.cpp',
            include_directories : libusermode_h,
            dependencies : [deps, utils_dep, check],
            link_with : libdrakvuf,
        )
        test('libusermode_printers_check', libusermode_printers_check)
    endif
endif
