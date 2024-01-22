incdir = include_directories('../..')
xc_incdir = dependency('xencontrol').get_pkgconfig_variable('includedir')
xl_incdir = dependency('xenlight').get_pkgconfig_variable('includedir')
xfm_incdir = dependency('xenforeignmemory').get_pkgconfig_variable('includedir')
xtl_incdir = dependency('xentoollog').get_pkgconfig_variable('includedir')

dl = meson.get_compiler('c').find_library('dl', required: true)

xen_helper = static_library('xen_helper',
    'xen_helper.c',

    include_directories : [incdir, xc_incdir],
    dependencies : [glib, dl]
)
