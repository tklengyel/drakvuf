syscalls  = syscalls/syscalls.cpp
syscalls += syscalls/syscalls.h
syscalls += syscalls/linux.cpp
syscalls += syscalls/linux.h
syscalls += syscalls/win.cpp
syscalls += syscalls/win.h
syscalls += syscalls/private.h

AM_CXXFLAGS += -Wno-return-type-c-linkage

lib_LTLIBRARIES += libdrakvufplugin_syscalls.la
libdrakvufplugin_syscalls_la_SOURCES= $(syscalls)
libdrakvufplugin_syscalls_la_LIBADD  = ../libdrakvuf/libdrakvuf.la
libdrakvufplugin_syscalls_la_LIBADD += libdrakvufplugins.la
