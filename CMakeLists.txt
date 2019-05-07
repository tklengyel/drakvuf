cmake_minimum_required (VERSION 3.0)

# set cmake module path, to search in cmake/modules first
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------

project(Drakvuf VERSION 0.6 LANGUAGES CXX C)

find_package(Git)
execute_process(COMMAND
    "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_SHA1
    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
)

#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------

include(CheckIncludeFiles)
check_include_files("fcntl.h;malloc.h;stdio.h;stdlib.h;string.h;sys/time.h;sys/mman.h;sys/inotify.h;syslog.h;unistd.h;errno.h;pthread.h" HEADERS)

find_library(PTHREAD pthread)

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0>=2.28)
pkg_search_module(VMI REQUIRED libvmi>=0.11)
pkg_search_module(JSONC REQUIRED json-c)

find_package(Xen)
find_package(LibVMI)

#-----------------------------------------------------------------------------
#                             BUILD OPTIONS
#-----------------------------------------------------------------------------

option(ENABLE_HARDENING "Enable hardening" ON)
option(ENABLE_SANITIZERS "Enable '-fsanitize' compile options" OFF)

option(ENABLE_PLUGIN_SYSCALLS "Enable the syscall tracing plugin" ON)
option(ENABLE_PLUGIN_POOLMON "Enable the kernel heap allocation tracer" ON)
option(ENABLE_PLUGIN_FILETRACER "Enable the file tracer plugin" ON)
option(ENABLE_PLUGIN_FILEDELETE "Enable the file delete catching plugin" ON)
option(ENABLE_PLUGIN_OBJMON "Enable the ObCreateObject watching plugin" ON)
option(ENABLE_PLUGIN_EXMON "Enable the KiDispatchException watching plugin" ON)
option(ENABLE_PLUGIN_SSDTMON "Enable the KiServiceTable watching plugin" ON)
option(ENABLE_PLUGIN_DEBUGMON "Enable the debug exception watching plugin" ON)
option(ENABLE_PLUGIN_DELAYMON "Enable the debug exception watching plugin" ON)
option(ENABLE_PLUGIN_CPUIDMON "Enable the CPUID watching plugin" ON)
option(ENABLE_PLUGIN_SOCKETMON "Enable the network socket watching plugin" ON)
option(ENABLE_PLUGIN_REGMON "Enable the windows registry watching plugin" ON)
option(ENABLE_PLUGIN_PROCMON "Enable the windows process lifecycle watching plugin" ON)
option(ENABLE_PLUGIN_BSODMON "Enable the windows kernel bugcheck watching plugin" ON)
option(ENABLE_PLUGIN_ENVMON "Enable the windows environment watching plugin" ON)
option(ENABLE_PLUGIN_CRASHMON "Enable the windows error reporting tool WerFault.exe watching plugin" ON)
option(ENABLE_PLUGIN_CLIPBOARDMON "Enable the clipboard tracing plugin" ON)
option(ENABLE_PLUGIN_WINDOWMON "Enable the windows tracing plugin" ON)
option(ENABLE_PLUGIN_LIBRARYMON "Enable the windows kernel bugcheck watching plugin" ON)
option(ENABLE_PLUGIN_DKOMMON "Enable the windows DKOM attacks watching plugin" ON)
option(ENABLE_PLUGIN_WMIMON "Enable the windows kernel bugcheck watching plugin" ON)

#-----------------------------------------------------------------------------
#                           BUILD TYPES & FLAGS
#-----------------------------------------------------------------------------

set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_C_STANDARD 11)

set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
set(CMAKE_CXX_STANDARD 11)

add_compile_options(
    "-Wall"
    "-Wextra"
    #"-Werror"
    "$<$<CONFIG:RELEASE>:-O2>"
    "$<$<CONFIG:DEBUG>:-g;-ggdb3;-O0;-DDRAKVUF_DEBUG;-Wno-missing-field-initializers;-Wcast-qual;-Wcast-align;-Wstrict-aliasing;-Wpointer-arith;-Winit-self;-Wshadow;-Wswitch-enum;-Wstrict-prototypes;-Wmissing-prototypes;-Wredundant-decls;-Wfloat-equal;-Wundef;-Wvla;-Wc++-compat>"
)
link_libraries("$<$<CONFIG:RELEASE>:-s>")

if (ENABLE_HARDENING)
    add_compile_options("-fno-strict-overflow;-D_FORTIFY_SOURCE=2;-fstack-protector-all;-Wstack-protector;--param;ssp-buffer-size=1;-fPIE")
    link_libraries("-pie -Wl,-z,relro -Wl,-z,now")
endif ()

if (ENABLE_SANITIZERS)
    add_compile_options("-fsanitize=address")
    add_compile_options("-fsanitize=leak")

    link_libraries("-fsanitize=address")
    link_libraries("-fsanitize=leak")
endif ()

#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------

configure_file(config.h.in ${PROJECT_BINARY_DIR}/config.h)

include_directories(${PROJECT_BINARY_DIR} ${GLIB_INCLUDE_DIRS})

set(drakvuf_src
    src/drakvuf.cpp
    src/main.cpp
    src/libdrakvuf/drakvuf.c
    src/libdrakvuf/linux-processes.c
    src/libdrakvuf/linux.c
    src/libdrakvuf/os.c
    src/libdrakvuf/rekall-profile.c
    src/libdrakvuf/vmi.c
    src/libdrakvuf/win-exports.c
    src/libdrakvuf/win-files.c
    src/libdrakvuf/win-handles.c
    src/libdrakvuf/win-processes.c
    src/libdrakvuf/win-registry.c
    src/libdrakvuf/win.c
    src/libinjector/injector.c
    src/libinjector/injector_stack.c
    src/xen_helper/xen_helper.c
    src/plugins/plugin_utils.cpp
    src/plugins/plugins.cpp
    src/plugins/plugins_ex.cpp
)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins")

if (ENABLE_PLUGIN_SYSCALLS)
    list(APPEND drakvuf_src src/plugins/syscalls/syscalls.cpp)
    include_directories("src/plugins/syscalls")
endif()

if (ENABLE_PLUGIN_POOLMON)
    list(APPEND drakvuf_src src/plugins/poolmon/poolmon.cpp)
    include_directories("src/plugins/poolmon")
endif()

if (ENABLE_PLUGIN_FILETRACER)
    list(APPEND drakvuf_src src/plugins/filetracer/filetracer.cpp
                            src/plugins/filetracer/win_acl.cpp)
    include_directories("src/plugins/filetracer")
endif()

if (ENABLE_PLUGIN_FILEDELETE)
    list(APPEND drakvuf_src src/plugins/filedelete/filedelete.cpp
                   src/plugins/filedelete/filedelete2_helpers.cpp)
    include_directories("src/plugins/filedelete")
endif()

if (ENABLE_PLUGIN_OBJMON)
    list(APPEND drakvuf_src src/plugins/objmon/objmon.cpp)
    include_directories("src/plugins/objmon")
endif()

if (ENABLE_PLUGIN_EXMON)
    list(APPEND drakvuf_src src/plugins/exmon/exmon.cpp)
    include_directories("src/plugins/exmon")
endif()

if (ENABLE_PLUGIN_SSDTMON)
    list(APPEND drakvuf_src src/plugins/ssdtmon/ssdtmon.cpp)
    include_directories("src/plugins/ssdtmon")
endif()

if (ENABLE_PLUGIN_DEBUGMON)
    list(APPEND drakvuf_src src/plugins/debugmon/debugmon.cpp)
    include_directories("src/plugins/debugmon")
endif()

if (ENABLE_PLUGIN_DELAYMON)
    list(APPEND drakvuf_src src/plugins/delaymon/delaymon.cpp)
    include_directories("src/plugins/delaymon")
endif()

if (ENABLE_PLUGIN_CPUIDMON)
    list(APPEND drakvuf_src src/plugins/cpuidmon/cpuidmon.cpp)
    include_directories("src/plugins/cpuidmon")
endif()

if (ENABLE_PLUGIN_SOCKETMON)
    list(APPEND drakvuf_src src/plugins/socketmon/socketmon.cpp)
    include_directories("src/plugins/socketmon")
endif()

if (ENABLE_PLUGIN_REGMON)
    list(APPEND drakvuf_src src/plugins/regmon/regmon.cpp)
    include_directories("src/plugins/regmon")
endif()

if (ENABLE_PLUGIN_PROCMON)
    list(APPEND drakvuf_src src/plugins/procmon/ntstatus.cpp
                   src/plugins/procmon/procmon.cpp
                   src/plugins/procmon/winnt.cpp)
    include_directories("src/plugins/procmon")
endif()

if (ENABLE_PLUGIN_BSODMON)
    list(APPEND drakvuf_src src/plugins/bsodmon/bsodmon.cpp
                   src/plugins/bsodmon/bugcheck.cpp)
    include_directories("src/plugins/bsodmon")
endif()

if (ENABLE_PLUGIN_ENVMON)
    list(APPEND drakvuf_src src/plugins/envmon/envmon.cpp)
    include_directories("src/plugins/envmon")
endif()

if (ENABLE_PLUGIN_CRASHMON)
    list(APPEND drakvuf_src src/plugins/crashmon/crashmon.cpp)
    include_directories("src/plugins/crashmon")
endif()

if (ENABLE_PLUGIN_CLIPBOARDMON)
    list(APPEND drakvuf_src src/plugins/clipboardmon/clipboardmon.cpp)
    include_directories("src/plugins/clipboardmon")
endif()

if (ENABLE_PLUGIN_WINDOWMON)
    list(APPEND drakvuf_src src/plugins/windowmon/windowmon.cpp)
    include_directories("src/plugins/windowmon")
endif()

if (ENABLE_PLUGIN_LIBRARYMON)
    list(APPEND drakvuf_src src/plugins/librarymon/librarymon.cpp)
    include_directories("src/plugins/librarymon")
endif()

if (ENABLE_PLUGIN_DKOMMON)
    list(APPEND drakvuf_src src/plugins/dkommon/dkommon.cpp)
    include_directories("src/plugins/dkommon")
endif()

if (ENABLE_PLUGIN_WMIMON)
    list(APPEND drakvuf_src src/plugins/wmimon/wmimon.cpp)
    include_directories("src/plugins/wmimon")
endif()

add_executable(drakvuf ${drakvuf_src})

target_include_directories(drakvuf PRIVATE ${LibVMI_INCLUDE_DIRS})
target_link_libraries(drakvuf PRIVATE ${LibVMI_LIBRARY})

target_include_directories(drakvuf PRIVATE ${GLIB_INCLUDE_DIRS})
target_link_libraries(drakvuf PRIVATE ${GLIB_LIBRARIES})

target_include_directories(drakvuf PRIVATE ${JSONC_INCLUDE_DIRS})
target_link_libraries(drakvuf PRIVATE ${JSONC_LIBRARIES})

target_link_libraries(drakvuf PRIVATE ${Xenctrl_LIBRARIES})

#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ C Flags      → ${CMAKE_C_FLAGS}")
message(STATUS " ↳ CXX Compiler → ${CMAKE_CXX_COMPILER}")
message(STATUS " ↳ CXX Flags    → ${CMAKE_CXX_FLAGS}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")

#-----------------------------------------------------------------------------
#                               INSTALL
#-----------------------------------------------------------------------------
install(TARGETS drakvuf DESTINATION bin)

#-----------------------------------------------------------------------------
#                               INSTALL
#-----------------------------------------------------------------------------
include(CTest)

add_test(NAME DrakvufRuns COMMAND drakvuf -h)
