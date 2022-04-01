libxc = dependency('xencontrol')
libxl = dependency('xenlight')
libxfm = dependency('xenforeignmemory')
libxtl = dependency('xentoollog')

xen_helper = static_library('xen_helper',
    'xen_helper.c',

    dependencies : [glib, libxc, libxl, libxfm, libxtl]
)
