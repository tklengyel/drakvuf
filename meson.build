project('drakvuf', 'c', 'cpp', version : '1.0')

subdir('mesontest')

add_project_arguments('-DHAVE_CONFIG_H', language : ['c', 'cpp'])
conf_data = configuration_data()
conf_data.set('name', meson.project_name())
conf_data.set('version', meson.project_version())
configure_file(input : 'config.h.in',
               output : 'config.h',
               configuration : conf_data)

glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
jsonc = dependency('json-c')

subdir('src/xen_helper')
subdir('src/libdrakvuf')
subdir('src/libinjector')

incdir = include_directories('.', 'src')

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
