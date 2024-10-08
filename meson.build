project('DRAKVUF (C) Tamas K Lengyel 2014-2024', 'c', 'cpp',
        version : '1.1',
        default_options : [
            'cpp_std=c++17',
            'buildtype=release',
            'strip=true',
            'default_library=static',
            'warning_level=2',
            'werror=true',
            'b_pie=true',
            'b_lto=true',
            'b_lto_mode=thin',
            'b_thinlto_cache=true',
            'b_ndebug=if-release'
        ]
)

# Check if C++ compiler is suitable
cpp=meson.get_compiler('cpp')
code='''int main(void) { bool test[2] = { [1] = 1, [0] = 0 }; return 0; }'''
if cpp.compiles(code) == false
    error('Unsupported C++ compiler, please install clang')
endif

# Find dependencies
glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
jsonc = dependency('json-c')
deps = [glib, libvmi, jsonc]

# Find optional dependencies
check = dependency('check', required : false)

# Set version string
version = meson.project_version()
if not get_option('release')
    version += '-' + run_command('git', 'describe', '--always', check: true).stdout().strip()
endif

# Setup for generating config.h
add_project_arguments('-DHAVE_CONFIG_H', language : ['c', 'cpp'])
config_h = configuration_data()
config_h.set_quoted('PACKAGE_NAME','DRAKVUF')
config_h.set_quoted('PACKAGE_VERSION', version)

# Ignore these warnings
add_project_arguments('-Wno-c99-designator', language : ['cpp'])
add_project_arguments('-Wno-reorder-init-list', language : ['cpp'])
add_project_arguments('-Wno-unknown-warning-option', language : ['cpp'])
add_project_arguments('-Wno-unused-parameter', language : ['c', 'cpp'])
add_project_arguments('-Wno-missing-field-initializers', language : ['c', 'cpp'])
add_project_arguments('-Wno-packed', language : ['c', 'cpp'])
add_project_arguments('-D_GLIBCXX_ASSERTIONS', language : ['cpp'])

if cpp.compiles(code, name: '-fstrict-flex-arrays=2', args: ['-fstrict-flex-arrays=2'])
    add_project_arguments('-fstrict-flex-arrays=2', language: ['c', 'cpp'])
endif

coverage_link_args=[]
hardened_link_args=[]

# Declare additional debug flags
if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDRAKVUF_DEBUG', language : ['c', 'cpp'])
    add_project_arguments('-ggdb3', language : ['c', 'cpp'])
    add_project_arguments('-Wformat', language : ['c', 'cpp'])
    add_project_arguments('-Wformat=2', language : ['c', 'cpp'])
    add_project_arguments('-Wformat-security', language : ['c', 'cpp'])
    add_project_arguments('-Wferror-limit=0', language : ['cpp'])
    add_project_arguments('-Wcast-qual', language : ['cpp'])
    add_project_arguments('-Wcast-align', language : ['cpp'])
    add_project_arguments('-Wstrict-aliasing', language : ['cpp'])
    add_project_arguments('-Wpointer-arith', language : ['cpp'])
    add_project_arguments('-Winit-self', language : ['cpp'])
    add_project_arguments('-Wshadow', language : ['cpp'])
    add_project_arguments('-Wredundant-decls', language : ['cpp'])
    add_project_arguments('-Wfloat-equal', language : ['cpp'])
    add_project_arguments('-Wundef', language : ['cpp'])
    add_project_arguments('-Wvla', language : ['cpp'])
    add_project_arguments('-Wextra-semi', language : ['c', 'cpp'])
    add_project_arguments('-ftrivial-auto-var-init=pattern', language: ['c', 'cpp'])
elif get_option('hardening')
    # Runtime hardening for release builds
    add_project_arguments('-Wno-strict-overflow', language : ['c', 'cpp'])
    add_project_arguments('-fno-strict-aliasing', language : ['c', 'cpp'])
    add_project_arguments('-U_FORTIFY_SOURCE', language : ['c', 'cpp'])
    add_project_arguments('-D_FORTIFY_SOURCE=3', language : ['c', 'cpp'])
    add_project_arguments('-fstack-protector-all', language : ['c', 'cpp'])
    add_project_arguments('--param', language : ['c', 'cpp'])
    add_project_arguments('ssp-buffer-size=1', language : ['c', 'cpp'])
    add_project_arguments('-fno-delete-null-pointer-checks', language : ['c', 'cpp'])
    add_project_arguments('-fwrapv', language : ['c', 'cpp'])

    code='''int test(int x) { int y=~x; return x+y; } int main(void) { return test(123); }'''
    if cpp.compiles(code, name: 'zero-vars', args: ['-ftrivial-auto-var-init=zero'])
        add_project_arguments('-ftrivial-auto-var-init=zero', language: ['c', 'cpp'])
    elif cpp.compiles(code, name: 'zero-vars2',
                      args: ['-ftrivial-auto-var-init=zero',
                             '-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang'])
        add_project_arguments('-ftrivial-auto-var-init=zero', language: ['c', 'cpp'])
        add_project_arguments('-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang', language: ['c', 'cpp'])
    endif

    code='''struct { void (*cb)(void); } s; void f(void) { s.cb(); }'''
    if cpp.compiles(code, name: '-fzero-call-used-regs=all', args: ['-O2', '-fzero-call-used-regs=all'])
        add_project_arguments('-fzero-call-used-regs=all', language: ['c', 'cpp'])
    endif

    if cpp.compiles(code, name: '-fstack-clash-protection', args: ['-fstack-clash-protection'])
        add_project_arguments('-fstack-clash-protection', language : ['c', 'cpp'])
    endif

    hardened_link_args += '-Wl,-z,nodlopen'
    hardened_link_args += '-Wl,-z,noexecstack'
    hardened_link_args += '-Wl,-z,relro'
    hardened_link_args += '-Wl,-z,now'
    config_h.set('HARDENING', 1)
endif

if get_option('coverage')
    add_project_arguments('-fprofile-instr-generate', language: ['c', 'cpp'])
    add_project_arguments('-fcoverage-mapping', language: ['c', 'cpp'])
    coverage_link_args += '-fprofile-instr-generate'
    coverage_link_args += '-fcoverage-mapping'
endif

if get_option('threadsafety')
    config_h.set('ENABLE_THREADSAFETY', 1)
endif

summary({
    'Build': version,
}, section: 'Version')

# Load meson.build from subdirs
subdir('src/xen_helper')
subdir('src/libdrakvuf')
subdir('src/libinjector')
subdir('src/libusermode')
subdir('src/libhook')
subdir('src/librepl')
subdir('src/plugins')

if get_option('ipt')
    config_h.set('ENABLE_IPT', 1)
endif

# Generate config.h
configure_file(output : 'config.h',
               configuration : config_h)

# Generate executables
incdir = include_directories('.', 'src')

executable('drakvuf',
    'src/main.cpp',
    'src/drakvuf.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : [libdrakvuf, drakvuf_plugins, libinjector],
    link_args : [hardened_link_args, coverage_link_args],
    install : true,
)

executable('injector',
    'src/injector.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : [libdrakvuf, libinjector],
    link_args : [hardened_link_args, coverage_link_args],
    install : true,
)

executable('proc_stat',
    'src/proc_stat.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : libdrakvuf,
    link_args : [hardened_link_args, coverage_link_args]
)

if get_option('xtf')
    executable('xtf',
               'src/xtf.c',

               include_directories : incdir,
               dependencies : deps,
               link_with : libdrakvuf,
    )
endif

if get_option('repl')
    executable('repl',
               'src/repl.cpp',

               include_directories : incdir,
               dependencies : deps,
               link_with : [libdrakvuf, librepl]
    )
endif

summary({
    'buildtype': get_option('buildtype'),
    'Hardening': get_option('hardening'),
    'XTF': get_option('xtf'),
    'REPL': get_option('repl'),
    'IPT': get_option('ipt'),
}, section: 'Configuration')

summary({
    'prefix/bindir': get_option('prefix') + '/' + get_option('bindir'),
}, section: 'Install path')
