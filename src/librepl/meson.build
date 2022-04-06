if get_option('repl').enabled()

    python3 = dependency('python3')
    python3embed = dependency('python3-embed')

    repl_h = include_directories(
        '..', '../..',
    )

    librepl = shared_library('repl',
        'repl.cpp',

        include_directories : repl_h,
        dependencies : [glib, libvmi, python3, python3embed],
        link_with : libdrakvuf
    )

    ctypesgen = find_program('ctypesgen')
    gensh = find_program('gen.sh')

    libdrakvufpy = custom_target('libdrakvuf.py',
        input : '../libdrakvuf/libdrakvuf.h',
        output : 'libdrakvuf.py',
        command : [gensh, ctypesgen, '@INPUT@', '@OUTPUT@'],
        build_by_default : true
    )

endif
