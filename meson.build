project('drakvuf', 'c', 'cpp', version : '1.0')
add_project_arguments('-DPACKAGE_NAME="drakvuf"', language : 'c')
add_project_arguments('-DPACKAGE_VERSION="1.0"', language : 'c')

subdir('mesontest')

glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
jsonc = dependency('json-c')

subdir('src/xen_helper')
subdir('src/libdrakvuf')
subdir('src/libinjector')

incdir = include_directories('src')

executable('injector',
    'src/injector.c',

    include_directories : incdir,
    dependencies : [glib, libvmi],
    link_with : [libdrakvuf, libinjector]
)

if get_option('xtf').enabled()
    executable('xtf',
           'src/xtf.c',

           include_directories : incdir,
           dependencies : [glib, libvmi],
           link_with : libdrakvuf
    )
endif
