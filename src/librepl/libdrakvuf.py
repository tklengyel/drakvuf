r"""Wrapper for libdrakvuf.h

Generated with:
/usr/local/bin/ctypesgen ../../src/libdrakvuf/libdrakvuf.h -I -I../.. -I../../src -I. -I/opt/libvmi/include -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/json-c -I/usr/include/python3.7m -I/usr/include/python3.7m -I/usr/include/python3.7m -I/usr/include/x86_64-linux-gnu/python3.7m -o libdrakvuf.py -l repl -L /shared/drakvuf/src

Do not modify this file.
"""

__docformat__ = "restructuredtext"

# Begin preamble for Python v(3, 2)

import ctypes, os, sys
from ctypes import *

_int_types = (c_int16, c_int32)
if hasattr(ctypes, "c_int64"):
    # Some builds of ctypes apparently do not have c_int64
    # defined; it's a pretty good bet that these builds do not
    # have 64-bit pointers.
    _int_types += (c_int64,)
for t in _int_types:
    if sizeof(t) == sizeof(c_size_t):
        c_ptrdiff_t = t
del t
del _int_types


class UserString:
    def __init__(self, seq):
        if isinstance(seq, bytes):
            self.data = seq
        elif isinstance(seq, UserString):
            self.data = seq.data[:]
        else:
            self.data = str(seq).encode()

    def __bytes__(self):
        return self.data

    def __str__(self):
        return self.data.decode()

    def __repr__(self):
        return repr(self.data)

    def __int__(self):
        return int(self.data.decode())

    def __long__(self):
        return int(self.data.decode())

    def __float__(self):
        return float(self.data.decode())

    def __complex__(self):
        return complex(self.data.decode())

    def __hash__(self):
        return hash(self.data)

    def __cmp__(self, string):
        if isinstance(string, UserString):
            return cmp(self.data, string.data)
        else:
            return cmp(self.data, string)

    def __le__(self, string):
        if isinstance(string, UserString):
            return self.data <= string.data
        else:
            return self.data <= string

    def __lt__(self, string):
        if isinstance(string, UserString):
            return self.data < string.data
        else:
            return self.data < string

    def __ge__(self, string):
        if isinstance(string, UserString):
            return self.data >= string.data
        else:
            return self.data >= string

    def __gt__(self, string):
        if isinstance(string, UserString):
            return self.data > string.data
        else:
            return self.data > string

    def __eq__(self, string):
        if isinstance(string, UserString):
            return self.data == string.data
        else:
            return self.data == string

    def __ne__(self, string):
        if isinstance(string, UserString):
            return self.data != string.data
        else:
            return self.data != string

    def __contains__(self, char):
        return char in self.data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        return self.__class__(self.data[index])

    def __getslice__(self, start, end):
        start = max(start, 0)
        end = max(end, 0)
        return self.__class__(self.data[start:end])

    def __add__(self, other):
        if isinstance(other, UserString):
            return self.__class__(self.data + other.data)
        elif isinstance(other, bytes):
            return self.__class__(self.data + other)
        else:
            return self.__class__(self.data + str(other).encode())

    def __radd__(self, other):
        if isinstance(other, bytes):
            return self.__class__(other + self.data)
        else:
            return self.__class__(str(other).encode() + self.data)

    def __mul__(self, n):
        return self.__class__(self.data * n)

    __rmul__ = __mul__

    def __mod__(self, args):
        return self.__class__(self.data % args)

    # the following methods are defined in alphabetical order:
    def capitalize(self):
        return self.__class__(self.data.capitalize())

    def center(self, width, *args):
        return self.__class__(self.data.center(width, *args))

    def count(self, sub, start=0, end=sys.maxsize):
        return self.data.count(sub, start, end)

    def decode(self, encoding=None, errors=None):  # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.decode(encoding, errors))
            else:
                return self.__class__(self.data.decode(encoding))
        else:
            return self.__class__(self.data.decode())

    def encode(self, encoding=None, errors=None):  # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.encode(encoding, errors))
            else:
                return self.__class__(self.data.encode(encoding))
        else:
            return self.__class__(self.data.encode())

    def endswith(self, suffix, start=0, end=sys.maxsize):
        return self.data.endswith(suffix, start, end)

    def expandtabs(self, tabsize=8):
        return self.__class__(self.data.expandtabs(tabsize))

    def find(self, sub, start=0, end=sys.maxsize):
        return self.data.find(sub, start, end)

    def index(self, sub, start=0, end=sys.maxsize):
        return self.data.index(sub, start, end)

    def isalpha(self):
        return self.data.isalpha()

    def isalnum(self):
        return self.data.isalnum()

    def isdecimal(self):
        return self.data.isdecimal()

    def isdigit(self):
        return self.data.isdigit()

    def islower(self):
        return self.data.islower()

    def isnumeric(self):
        return self.data.isnumeric()

    def isspace(self):
        return self.data.isspace()

    def istitle(self):
        return self.data.istitle()

    def isupper(self):
        return self.data.isupper()

    def join(self, seq):
        return self.data.join(seq)

    def ljust(self, width, *args):
        return self.__class__(self.data.ljust(width, *args))

    def lower(self):
        return self.__class__(self.data.lower())

    def lstrip(self, chars=None):
        return self.__class__(self.data.lstrip(chars))

    def partition(self, sep):
        return self.data.partition(sep)

    def replace(self, old, new, maxsplit=-1):
        return self.__class__(self.data.replace(old, new, maxsplit))

    def rfind(self, sub, start=0, end=sys.maxsize):
        return self.data.rfind(sub, start, end)

    def rindex(self, sub, start=0, end=sys.maxsize):
        return self.data.rindex(sub, start, end)

    def rjust(self, width, *args):
        return self.__class__(self.data.rjust(width, *args))

    def rpartition(self, sep):
        return self.data.rpartition(sep)

    def rstrip(self, chars=None):
        return self.__class__(self.data.rstrip(chars))

    def split(self, sep=None, maxsplit=-1):
        return self.data.split(sep, maxsplit)

    def rsplit(self, sep=None, maxsplit=-1):
        return self.data.rsplit(sep, maxsplit)

    def splitlines(self, keepends=0):
        return self.data.splitlines(keepends)

    def startswith(self, prefix, start=0, end=sys.maxsize):
        return self.data.startswith(prefix, start, end)

    def strip(self, chars=None):
        return self.__class__(self.data.strip(chars))

    def swapcase(self):
        return self.__class__(self.data.swapcase())

    def title(self):
        return self.__class__(self.data.title())

    def translate(self, *args):
        return self.__class__(self.data.translate(*args))

    def upper(self):
        return self.__class__(self.data.upper())

    def zfill(self, width):
        return self.__class__(self.data.zfill(width))


class MutableString(UserString):
    """mutable string objects

    Python strings are immutable objects.  This has the advantage, that
    strings may be used as dictionary keys.  If this property isn't needed
    and you insist on changing string values in place instead, you may cheat
    and use MutableString.

    But the purpose of this class is an educational one: to prevent
    people from inventing their own mutable string class derived
    from UserString and than forget thereby to remove (override) the
    __hash__ method inherited from UserString.  This would lead to
    errors that would be very hard to track down.

    A faster and better solution is to rewrite your program using lists."""

    def __init__(self, string=""):
        self.data = string

    def __hash__(self):
        raise TypeError("unhashable type (it is mutable)")

    def __setitem__(self, index, sub):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data):
            raise IndexError
        self.data = self.data[:index] + sub + self.data[index + 1 :]

    def __delitem__(self, index):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data):
            raise IndexError
        self.data = self.data[:index] + self.data[index + 1 :]

    def __setslice__(self, start, end, sub):
        start = max(start, 0)
        end = max(end, 0)
        if isinstance(sub, UserString):
            self.data = self.data[:start] + sub.data + self.data[end:]
        elif isinstance(sub, bytes):
            self.data = self.data[:start] + sub + self.data[end:]
        else:
            self.data = self.data[:start] + str(sub).encode() + self.data[end:]

    def __delslice__(self, start, end):
        start = max(start, 0)
        end = max(end, 0)
        self.data = self.data[:start] + self.data[end:]

    def immutable(self):
        return UserString(self.data)

    def __iadd__(self, other):
        if isinstance(other, UserString):
            self.data += other.data
        elif isinstance(other, bytes):
            self.data += other
        else:
            self.data += str(other).encode()
        return self

    def __imul__(self, n):
        self.data *= n
        return self


class String(MutableString, Union):

    _fields_ = [("raw", POINTER(c_char)), ("data", c_char_p)]

    def __init__(self, obj=""):
        if isinstance(obj, (bytes, UserString)):
            self.data = bytes(obj)
        else:
            self.raw = obj

    def __len__(self):
        return self.data and len(self.data) or 0

    def from_param(cls, obj):
        # Convert None or 0
        if obj is None or obj == 0:
            return cls(POINTER(c_char)())

        # Convert from String
        elif isinstance(obj, String):
            return obj

        # Convert from bytes
        elif isinstance(obj, bytes):
            return cls(obj)

        # Convert from str
        elif isinstance(obj, str):
            return cls(obj.encode())

        # Convert from c_char_p
        elif isinstance(obj, c_char_p):
            return obj

        # Convert from POINTER(c_char)
        elif isinstance(obj, POINTER(c_char)):
            return obj

        # Convert from raw pointer
        elif isinstance(obj, int):
            return cls(cast(obj, POINTER(c_char)))

        # Convert from c_char array
        elif isinstance(obj, c_char * len(obj)):
            return obj

        # Convert from object
        else:
            return String.from_param(obj._as_parameter_)

    from_param = classmethod(from_param)


def ReturnString(obj, func=None, arguments=None):
    return String.from_param(obj)


# As of ctypes 1.0, ctypes does not support custom error-checking
# functions on callbacks, nor does it support custom datatypes on
# callbacks, so we must ensure that all callbacks return
# primitive datatypes.
#
# Non-primitive return values wrapped with UNCHECKED won't be
# typechecked, and will be converted to c_void_p.
def UNCHECKED(type):
    if hasattr(type, "_type_") and isinstance(type._type_, str) and type._type_ != "P":
        return type
    else:
        return c_void_p


# ctypes doesn't have direct support for variadic functions, so we have to write
# our own wrapper class
class _variadic_function(object):
    def __init__(self, func, restype, argtypes, errcheck):
        self.func = func
        self.func.restype = restype
        self.argtypes = argtypes
        if errcheck:
            self.func.errcheck = errcheck

    def _as_parameter_(self):
        # So we can pass this variadic function as a function pointer
        return self.func

    def __call__(self, *args):
        fixed_args = []
        i = 0
        for argtype in self.argtypes:
            # Typecheck what we can
            fixed_args.append(argtype.from_param(args[i]))
            i += 1
        return self.func(*fixed_args + list(args[i:]))


def ord_if_char(value):
    """
    Simple helper used for casts to simple builtin types:  if the argument is a
    string type, it will be converted to it's ordinal value.

    This function will raise an exception if the argument is string with more
    than one characters.
    """
    return ord(value) if (isinstance(value, bytes) or isinstance(value, str)) else value

# End preamble

_libs = {}
_libdirs = ['/shared/drakvuf/src']

# Begin loader

# ----------------------------------------------------------------------------
# Copyright (c) 2008 David James
# Copyright (c) 2006-2008 Alex Holkner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of pyglet nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ----------------------------------------------------------------------------

import os.path, re, sys, glob
import platform
import ctypes
import ctypes.util


def _environ_path(name):
    if name in os.environ:
        return os.environ[name].split(":")
    else:
        return []


class LibraryLoader(object):
    # library names formatted specifically for platforms
    name_formats = ["%s"]

    class Lookup(object):
        mode = ctypes.DEFAULT_MODE

        def __init__(self, path):
            super(LibraryLoader.Lookup, self).__init__()
            self.access = dict(cdecl=ctypes.CDLL(path, self.mode))

        def get(self, name, calling_convention="cdecl"):
            if calling_convention not in self.access:
                raise LookupError(
                    "Unknown calling convention '{}' for function '{}'".format(
                        calling_convention, name
                    )
                )
            return getattr(self.access[calling_convention], name)

        def has(self, name, calling_convention="cdecl"):
            if calling_convention not in self.access:
                return False
            return hasattr(self.access[calling_convention], name)

        def __getattr__(self, name):
            return getattr(self.access["cdecl"], name)

    def __init__(self):
        self.other_dirs = []

    def __call__(self, libname):
        """Given the name of a library, load it."""
        paths = self.getpaths(libname)

        for path in paths:
            try:
                return self.Lookup(path)
            except:
                pass

        raise ImportError("Could not load %s." % libname)

    def getpaths(self, libname):
        """Return a list of paths where the library might be found."""
        if os.path.isabs(libname):
            yield libname
        else:
            # search through a prioritized series of locations for the library

            # we first search any specific directories identified by user
            for dir_i in self.other_dirs:
                for fmt in self.name_formats:
                    # dir_i should be absolute already
                    yield os.path.join(dir_i, fmt % libname)

            # then we search the directory where the generated python interface is stored
            for fmt in self.name_formats:
                yield os.path.abspath(os.path.join(os.path.dirname(__file__), fmt % libname))

            # now, use the ctypes tools to try to find the library
            for fmt in self.name_formats:
                path = ctypes.util.find_library(fmt % libname)
                if path:
                    yield path

            # then we search all paths identified as platform-specific lib paths
            for path in self.getplatformpaths(libname):
                yield path

            # Finally, we'll try the users current working directory
            for fmt in self.name_formats:
                yield os.path.abspath(os.path.join(os.path.curdir, fmt % libname))

    def getplatformpaths(self, libname):
        return []


# Darwin (Mac OS X)


class DarwinLibraryLoader(LibraryLoader):
    name_formats = [
        "lib%s.dylib",
        "lib%s.so",
        "lib%s.bundle",
        "%s.dylib",
        "%s.so",
        "%s.bundle",
        "%s",
    ]

    class Lookup(LibraryLoader.Lookup):
        # Darwin requires dlopen to be called with mode RTLD_GLOBAL instead
        # of the default RTLD_LOCAL.  Without this, you end up with
        # libraries not being loadable, resulting in "Symbol not found"
        # errors
        mode = ctypes.RTLD_GLOBAL

    def getplatformpaths(self, libname):
        if os.path.pathsep in libname:
            names = [libname]
        else:
            names = [format % libname for format in self.name_formats]

        for dir in self.getdirs(libname):
            for name in names:
                yield os.path.join(dir, name)

    def getdirs(self, libname):
        """Implements the dylib search as specified in Apple documentation:

        http://developer.apple.com/documentation/DeveloperTools/Conceptual/
            DynamicLibraries/Articles/DynamicLibraryUsageGuidelines.html

        Before commencing the standard search, the method first checks
        the bundle's ``Frameworks`` directory if the application is running
        within a bundle (OS X .app).
        """

        dyld_fallback_library_path = _environ_path("DYLD_FALLBACK_LIBRARY_PATH")
        if not dyld_fallback_library_path:
            dyld_fallback_library_path = [os.path.expanduser("~/lib"), "/usr/local/lib", "/usr/lib"]

        dirs = []

        if "/" in libname:
            dirs.extend(_environ_path("DYLD_LIBRARY_PATH"))
        else:
            dirs.extend(_environ_path("LD_LIBRARY_PATH"))
            dirs.extend(_environ_path("DYLD_LIBRARY_PATH"))

        if hasattr(sys, "frozen") and sys.frozen == "macosx_app":
            dirs.append(os.path.join(os.environ["RESOURCEPATH"], "..", "Frameworks"))

        dirs.extend(dyld_fallback_library_path)

        return dirs


# Posix


class PosixLibraryLoader(LibraryLoader):
    _ld_so_cache = None

    _include = re.compile(r"^\s*include\s+(?P<pattern>.*)")

    class _Directories(dict):
        def __init__(self):
            self.order = 0

        def add(self, directory):
            if len(directory) > 1:
                directory = directory.rstrip(os.path.sep)
            # only adds and updates order if exists and not already in set
            if not os.path.exists(directory):
                return
            o = self.setdefault(directory, self.order)
            if o == self.order:
                self.order += 1

        def extend(self, directories):
            for d in directories:
                self.add(d)

        def ordered(self):
            return (i[0] for i in sorted(self.items(), key=lambda D: D[1]))

    def _get_ld_so_conf_dirs(self, conf, dirs):
        """
        Recursive funtion to help parse all ld.so.conf files, including proper
        handling of the `include` directive.
        """

        try:
            with open(conf) as f:
                for D in f:
                    D = D.strip()
                    if not D:
                        continue

                    m = self._include.match(D)
                    if not m:
                        dirs.add(D)
                    else:
                        for D2 in glob.glob(m.group("pattern")):
                            self._get_ld_so_conf_dirs(D2, dirs)
        except IOError:
            pass

    def _create_ld_so_cache(self):
        # Recreate search path followed by ld.so.  This is going to be
        # slow to build, and incorrect (ld.so uses ld.so.cache, which may
        # not be up-to-date).  Used only as fallback for distros without
        # /sbin/ldconfig.
        #
        # We assume the DT_RPATH and DT_RUNPATH binary sections are omitted.

        directories = self._Directories()
        for name in (
            "LD_LIBRARY_PATH",
            "SHLIB_PATH",  # HPUX
            "LIBPATH",  # OS/2, AIX
            "LIBRARY_PATH",  # BE/OS
        ):
            if name in os.environ:
                directories.extend(os.environ[name].split(os.pathsep))

        self._get_ld_so_conf_dirs("/etc/ld.so.conf", directories)

        bitage = platform.architecture()[0]

        unix_lib_dirs_list = []
        if bitage.startswith("64"):
            # prefer 64 bit if that is our arch
            unix_lib_dirs_list += ["/lib64", "/usr/lib64"]

        # must include standard libs, since those paths are also used by 64 bit
        # installs
        unix_lib_dirs_list += ["/lib", "/usr/lib"]
        if sys.platform.startswith("linux"):
            # Try and support multiarch work in Ubuntu
            # https://wiki.ubuntu.com/MultiarchSpec
            if bitage.startswith("32"):
                # Assume Intel/AMD x86 compat
                unix_lib_dirs_list += ["/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu"]
            elif bitage.startswith("64"):
                # Assume Intel/AMD x86 compat
                unix_lib_dirs_list += ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]
            else:
                # guess...
                unix_lib_dirs_list += glob.glob("/lib/*linux-gnu")
        directories.extend(unix_lib_dirs_list)

        cache = {}
        lib_re = re.compile(r"lib(.*)\.s[ol]")
        ext_re = re.compile(r"\.s[ol]$")
        for dir in directories.ordered():
            try:
                for path in glob.glob("%s/*.s[ol]*" % dir):
                    file = os.path.basename(path)

                    # Index by filename
                    cache_i = cache.setdefault(file, set())
                    cache_i.add(path)

                    # Index by library name
                    match = lib_re.match(file)
                    if match:
                        library = match.group(1)
                        cache_i = cache.setdefault(library, set())
                        cache_i.add(path)
            except OSError:
                pass

        self._ld_so_cache = cache

    def getplatformpaths(self, libname):
        if self._ld_so_cache is None:
            self._create_ld_so_cache()

        result = self._ld_so_cache.get(libname, set())
        for i in result:
            # we iterate through all found paths for library, since we may have
            # actually found multiple architectures or other library types that
            # may not load
            yield i


# Windows


class WindowsLibraryLoader(LibraryLoader):
    name_formats = ["%s.dll", "lib%s.dll", "%slib.dll", "%s"]

    class Lookup(LibraryLoader.Lookup):
        def __init__(self, path):
            super(WindowsLibraryLoader.Lookup, self).__init__(path)
            self.access["stdcall"] = ctypes.windll.LoadLibrary(path)


# Platform switching

# If your value of sys.platform does not appear in this dict, please contact
# the Ctypesgen maintainers.

loaderclass = {
    "darwin": DarwinLibraryLoader,
    "cygwin": WindowsLibraryLoader,
    "win32": WindowsLibraryLoader,
    "msys": WindowsLibraryLoader,
}

load_library = loaderclass.get(sys.platform, PosixLibraryLoader)()


def add_library_search_dirs(other_dirs):
    """
    Add libraries to search paths.
    If library paths are relative, convert them to absolute with respect to this
    file's directory
    """
    for F in other_dirs:
        if not os.path.isabs(F):
            F = os.path.abspath(F)
        load_library.other_dirs.append(F)


del loaderclass

# End loader

add_library_search_dirs(['/shared/drakvuf/src'])

# Begin libraries
_libs["repl"] = load_library("repl")

# 1 libraries
# End libraries

# No modules

gint64 = c_long# /usr/lib/x86_64-linux-gnu/glib-2.0/include/glibconfig.h: 61

gchar = c_char# /usr/include/glib-2.0/glib/gtypes.h: 46

register_t = c_int# /usr/include/x86_64-linux-gnu/sys/types.h: 169

enum_os = c_int# /opt/libvmi/include/libvmi/libvmi.h: 123

os_t = enum_os# /opt/libvmi/include/libvmi/libvmi.h: 123

enum_page_mode = c_int# /opt/libvmi/include/libvmi/libvmi.h: 171

page_mode_t = enum_page_mode# /opt/libvmi/include/libvmi/libvmi.h: 171

# /opt/libvmi/include/libvmi/libvmi.h: 575
class struct_x86_regs(Structure):
    pass

struct_x86_regs.__slots__ = [
    'rax',
    'rcx',
    'rdx',
    'rbx',
    'rsp',
    'rbp',
    'rsi',
    'rdi',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'rflags',
    'dr6',
    'dr7',
    'rip',
    'cr0',
    'cr2',
    'cr3',
    'cr4',
    'sysenter_cs',
    'sysenter_esp',
    'sysenter_eip',
    'msr_efer',
    'msr_star',
    'msr_lstar',
    'msr_pat',
    'msr_cstar',
    'fs_base',
    'fs_limit',
    'fs_sel',
    'fs_arbytes',
    'gs_base',
    'gs_limit',
    'gs_sel',
    'gs_arbytes',
    'cs_base',
    'cs_limit',
    'cs_sel',
    'cs_arbytes',
    'ss_base',
    'ss_limit',
    'ss_sel',
    'ss_arbytes',
    'ds_base',
    'ds_limit',
    'ds_sel',
    'ds_arbytes',
    'es_base',
    'es_limit',
    'es_sel',
    'es_arbytes',
    'shadow_gs',
    'idtr_base',
    'idtr_limit',
    'gdtr_base',
    'gdtr_limit',
    '_pad',
]
struct_x86_regs._fields_ = [
    ('rax', c_uint64),
    ('rcx', c_uint64),
    ('rdx', c_uint64),
    ('rbx', c_uint64),
    ('rsp', c_uint64),
    ('rbp', c_uint64),
    ('rsi', c_uint64),
    ('rdi', c_uint64),
    ('r8', c_uint64),
    ('r9', c_uint64),
    ('r10', c_uint64),
    ('r11', c_uint64),
    ('r12', c_uint64),
    ('r13', c_uint64),
    ('r14', c_uint64),
    ('r15', c_uint64),
    ('rflags', c_uint64),
    ('dr6', c_uint64),
    ('dr7', c_uint64),
    ('rip', c_uint64),
    ('cr0', c_uint64),
    ('cr2', c_uint64),
    ('cr3', c_uint64),
    ('cr4', c_uint64),
    ('sysenter_cs', c_uint64),
    ('sysenter_esp', c_uint64),
    ('sysenter_eip', c_uint64),
    ('msr_efer', c_uint64),
    ('msr_star', c_uint64),
    ('msr_lstar', c_uint64),
    ('msr_pat', c_uint64),
    ('msr_cstar', c_uint64),
    ('fs_base', c_uint64),
    ('fs_limit', c_uint64),
    ('fs_sel', c_uint64),
    ('fs_arbytes', c_uint64),
    ('gs_base', c_uint64),
    ('gs_limit', c_uint64),
    ('gs_sel', c_uint64),
    ('gs_arbytes', c_uint64),
    ('cs_base', c_uint64),
    ('cs_limit', c_uint64),
    ('cs_sel', c_uint64),
    ('cs_arbytes', c_uint32),
    ('ss_base', c_uint64),
    ('ss_limit', c_uint64),
    ('ss_sel', c_uint64),
    ('ss_arbytes', c_uint64),
    ('ds_base', c_uint64),
    ('ds_limit', c_uint64),
    ('ds_sel', c_uint64),
    ('ds_arbytes', c_uint64),
    ('es_base', c_uint64),
    ('es_limit', c_uint64),
    ('es_sel', c_uint64),
    ('es_arbytes', c_uint64),
    ('shadow_gs', c_uint64),
    ('idtr_base', c_uint64),
    ('idtr_limit', c_uint64),
    ('gdtr_base', c_uint64),
    ('gdtr_limit', c_uint64),
    ('_pad', c_uint32),
]

x86_registers_t = struct_x86_regs# /opt/libvmi/include/libvmi/libvmi.h: 575

# /opt/libvmi/include/libvmi/libvmi.h: 584
class struct_arm_registers(Structure):
    pass

struct_arm_registers.__slots__ = [
    'ttbr0',
    'ttbr1',
    'ttbcr',
    'pc',
    'cpsr',
    '_pad',
]
struct_arm_registers._fields_ = [
    ('ttbr0', c_uint64),
    ('ttbr1', c_uint64),
    ('ttbcr', c_uint64),
    ('pc', c_uint64),
    ('cpsr', c_uint32),
    ('_pad', c_uint32),
]

arm_registers_t = struct_arm_registers# /opt/libvmi/include/libvmi/libvmi.h: 584

# /opt/libvmi/include/libvmi/libvmi.h: 587
class union_anon_134(Union):
    pass

union_anon_134.__slots__ = [
    'x86',
    'arm',
]
union_anon_134._fields_ = [
    ('x86', x86_registers_t),
    ('arm', arm_registers_t),
]

# /opt/libvmi/include/libvmi/libvmi.h: 591
class struct_registers(Structure):
    pass

struct_registers.__slots__ = [
    'unnamed_1',
]
struct_registers._anonymous_ = [
    'unnamed_1',
]
struct_registers._fields_ = [
    ('unnamed_1', union_anon_134),
]

registers_t = struct_registers# /opt/libvmi/include/libvmi/libvmi.h: 591

addr_t = c_uint64# /opt/libvmi/include/libvmi/libvmi.h: 602

vmi_pid_t = c_int32# /opt/libvmi/include/libvmi/libvmi.h: 607

enum_translation_mechanism = c_int# /opt/libvmi/include/libvmi/libvmi.h: 675

translation_mechanism_t = enum_translation_mechanism# /opt/libvmi/include/libvmi/libvmi.h: 675

# /opt/libvmi/include/libvmi/libvmi.h: 699
class struct_anon_141(Structure):
    pass

struct_anon_141.__slots__ = [
    'translate_mechanism',
    'addr',
    'ksym',
    'dtb',
    'pid',
]
struct_anon_141._fields_ = [
    ('translate_mechanism', translation_mechanism_t),
    ('addr', addr_t),
    ('ksym', String),
    ('dtb', addr_t),
    ('pid', vmi_pid_t),
]

access_context_t = struct_anon_141# /opt/libvmi/include/libvmi/libvmi.h: 699

# /opt/libvmi/include/libvmi/libvmi.h: 721
class struct__ustring(Structure):
    pass

struct__ustring.__slots__ = [
    'length',
    'contents',
    'encoding',
]
struct__ustring._fields_ = [
    ('length', c_size_t),
    ('contents', POINTER(c_uint8)),
    ('encoding', String),
]

unicode_string_t = struct__ustring# /opt/libvmi/include/libvmi/libvmi.h: 721

# /opt/libvmi/include/libvmi/libvmi.h: 731
class struct_vmi_instance(Structure):
    pass

vmi_instance_t = POINTER(struct_vmi_instance)# /opt/libvmi/include/libvmi/libvmi.h: 731

# /usr/include/json-c/json_object.h: 71
class struct_json_object(Structure):
    pass

json_object = struct_json_object# /usr/include/json-c/json_object.h: 81

vmi_mem_access_t = c_uint8# /opt/libvmi/include/libvmi/events.h: 95

# /opt/libvmi/include/libvmi/events.h: 392
class struct_anon_152(Structure):
    pass

struct_anon_152.__slots__ = [
    'gla',
    'gfn',
    'offset',
    'insn_length',
    'type',
    'reinject',
    '_pad',
]
struct_anon_152._fields_ = [
    ('gla', addr_t),
    ('gfn', addr_t),
    ('offset', addr_t),
    ('insn_length', c_uint32),
    ('type', c_uint8),
    ('reinject', c_int8),
    ('_pad', c_uint16),
]

debug_event_t = struct_anon_152# /opt/libvmi/include/libvmi/events.h: 392

# /opt/libvmi/include/libvmi/events.h: 399
class struct_anon_153(Structure):
    pass

struct_anon_153.__slots__ = [
    'insn_length',
    'leaf',
    'subleaf',
    '_pad',
]
struct_anon_153._fields_ = [
    ('insn_length', c_uint32),
    ('leaf', c_uint32),
    ('subleaf', c_uint32),
    ('_pad', c_uint32),
]

cpuid_event_t = struct_anon_153# /opt/libvmi/include/libvmi/events.h: 399

event_response_t = c_uint32# /opt/libvmi/include/libvmi/events.h: 447

enum_lookup_type = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

__INVALID_LOOKUP_TYPE = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

LOOKUP_NONE = (__INVALID_LOOKUP_TYPE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

LOOKUP_DTB = (LOOKUP_NONE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

LOOKUP_PID = (LOOKUP_DTB + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

LOOKUP_NAME = (LOOKUP_PID + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

lookup_type_t = enum_lookup_type# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 144

enum_addr_type = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

__INVALID_ADDR_TYPE = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

ADDR_RVA = (__INVALID_ADDR_TYPE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

ADDR_VA = (ADDR_RVA + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

ADDR_PA = (ADDR_VA + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

addr_type_t = enum_addr_type# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 152

enum_trap_type = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

__INVALID_TRAP_TYPE = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

BREAKPOINT = (__INVALID_TRAP_TYPE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

MEMACCESS = (BREAKPOINT + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

REGISTER = (MEMACCESS + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

DEBUG = (REGISTER + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

CPUID = (DEBUG + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

trap_type_t = enum_trap_type# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 162

enum_memaccess_type = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 169

__INVALID_MEMACCESS_TYPE = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 169

PRE = (__INVALID_MEMACCESS_TYPE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 169

POST = (PRE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 169

memaccess_type_t = enum_memaccess_type# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 169

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 179
class struct_process_data(Structure):
    pass

struct_process_data.__slots__ = [
    'name',
    'pid',
    'ppid',
    'base_addr',
    'userid',
    'tid',
]
struct_process_data._fields_ = [
    ('name', String),
    ('pid', vmi_pid_t),
    ('ppid', vmi_pid_t),
    ('base_addr', addr_t),
    ('userid', c_int64),
    ('tid', c_uint32),
]

proc_data_t = struct_process_data# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 179

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 181
class struct_drakvuf(Structure):
    pass

drakvuf_t = POINTER(struct_drakvuf)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 181

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 202
class struct_drakvuf_trap(Structure):
    pass

drakvuf_trap_t = struct_drakvuf_trap# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 183

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 195
class union_anon_159(Union):
    pass

union_anon_159.__slots__ = [
    'cpuid',
    'debug',
]
union_anon_159._fields_ = [
    ('cpuid', POINTER(cpuid_event_t)),
    ('debug', POINTER(debug_event_t)),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 200
class struct_drakvuf_trap_info(Structure):
    pass

struct_drakvuf_trap_info.__slots__ = [
    'timestamp',
    'vcpu',
    'altp2m_idx',
    'proc_data',
    'attached_proc_data',
    'trap_pa',
    'regs',
    'trap',
    'unnamed_1',
]
struct_drakvuf_trap_info._anonymous_ = [
    'unnamed_1',
]
struct_drakvuf_trap_info._fields_ = [
    ('timestamp', gint64),
    ('vcpu', c_uint),
    ('altp2m_idx', c_uint16),
    ('proc_data', proc_data_t),
    ('attached_proc_data', proc_data_t),
    ('trap_pa', addr_t),
    ('regs', POINTER(x86_registers_t)),
    ('trap', POINTER(drakvuf_trap_t)),
    ('unnamed_1', union_anon_159),
]

drakvuf_trap_info_t = struct_drakvuf_trap_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 200

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 208
class union_anon_160(Union):
    pass

union_anon_160.__slots__ = [
    'name',
    '_name',
]
union_anon_160._fields_ = [
    ('name', String),
    ('_name', POINTER(None)),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 219
class union_anon_161(Union):
    pass

union_anon_161.__slots__ = [
    'pid',
    'proc',
    'dtb',
]
union_anon_161._fields_ = [
    ('pid', vmi_pid_t),
    ('proc', String),
    ('dtb', addr_t),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 232
class union_anon_162(Union):
    pass

union_anon_162.__slots__ = [
    'rva',
    'addr',
]
union_anon_162._fields_ = [
    ('rva', addr_t),
    ('addr', addr_t),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 216
class struct_anon_163(Structure):
    pass

struct_anon_163.__slots__ = [
    'lookup_type',
    'unnamed_1',
    'module',
    'addr_type',
    'unnamed_2',
]
struct_anon_163._anonymous_ = [
    'unnamed_1',
    'unnamed_2',
]
struct_anon_163._fields_ = [
    ('lookup_type', lookup_type_t),
    ('unnamed_1', union_anon_161),
    ('module', String),
    ('addr_type', addr_type_t),
    ('unnamed_2', union_anon_162),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 239
class struct_anon_164(Structure):
    pass

struct_anon_164.__slots__ = [
    'gfn',
    'access',
    'type',
]
struct_anon_164._fields_ = [
    ('gfn', addr_t),
    ('access', vmi_mem_access_t),
    ('type', memaccess_type_t),
]

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 214
class union_anon_165(Union):
    pass

union_anon_165.__slots__ = [
    'breakpoint',
    'memaccess',
    'reg',
]
union_anon_165._fields_ = [
    ('breakpoint', struct_anon_163),
    ('memaccess', struct_anon_164),
    ('reg', register_t),
]

struct_drakvuf_trap.__slots__ = [
    'type',
    'cb',
    'data',
    'unnamed_1',
    'unnamed_2',
]
struct_drakvuf_trap._anonymous_ = [
    'unnamed_1',
    'unnamed_2',
]
struct_drakvuf_trap._fields_ = [
    ('type', trap_type_t),
    ('cb', CFUNCTYPE(UNCHECKED(event_response_t), drakvuf_t, POINTER(drakvuf_trap_info_t))),
    ('data', POINTER(None)),
    ('unnamed_1', union_anon_160),
    ('unnamed_2', union_anon_165),
]

enum_privilege_mode = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 262

KERNEL_MODE = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 262

USER_MODE = (KERNEL_MODE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 262

MAXIMUM_MODE = (USER_MODE + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 262

privilege_mode_t = enum_privilege_mode# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 262

enum_object_manager_object = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 269

OBJ_MANAGER_PROCESS_OBJECT = 7# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 269

OBJ_MANAGER_THREAD_OBJECT = 8# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 269

object_manager_object_t = enum_object_manager_object# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 269

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 273
if _libs["repl"].has("drakvuf_lock_and_get_vmi", "cdecl"):
    drakvuf_lock_and_get_vmi = _libs["repl"].get("drakvuf_lock_and_get_vmi", "cdecl")
    drakvuf_lock_and_get_vmi.argtypes = [drakvuf_t]
    drakvuf_lock_and_get_vmi.restype = vmi_instance_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 274
if _libs["repl"].has("drakvuf_release_vmi", "cdecl"):
    drakvuf_release_vmi = _libs["repl"].get("drakvuf_release_vmi", "cdecl")
    drakvuf_release_vmi.argtypes = [drakvuf_t]
    drakvuf_release_vmi.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 288
class struct_symbol(Structure):
    pass

struct_symbol.__slots__ = [
    'name',
    'rva',
    'type',
    'inputs',
]
struct_symbol._fields_ = [
    ('name', String),
    ('rva', addr_t),
    ('type', c_uint8),
    ('inputs', c_int),
]

symbol_t = struct_symbol# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 288

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 295
class struct_symbols(Structure):
    pass

struct_symbols.__slots__ = [
    'name',
    'symbols',
    'count',
]
struct_symbols._fields_ = [
    ('name', String),
    ('symbols', POINTER(symbol_t)),
    ('count', c_uint64),
]

symbols_t = struct_symbols# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 295

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 297
if _libs["repl"].has("drakvuf_get_json_wow_path", "cdecl"):
    drakvuf_get_json_wow_path = _libs["repl"].get("drakvuf_get_json_wow_path", "cdecl")
    drakvuf_get_json_wow_path.argtypes = [drakvuf_t]
    drakvuf_get_json_wow_path.restype = c_char_p

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 298
if _libs["repl"].has("drakvuf_get_json_wow", "cdecl"):
    drakvuf_get_json_wow = _libs["repl"].get("drakvuf_get_json_wow", "cdecl")
    drakvuf_get_json_wow.argtypes = [drakvuf_t]
    drakvuf_get_json_wow.restype = POINTER(json_object)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 300
if _libs["repl"].has("json_get_symbols", "cdecl"):
    json_get_symbols = _libs["repl"].get("json_get_symbols", "cdecl")
    json_get_symbols.argtypes = [POINTER(json_object)]
    json_get_symbols.restype = POINTER(symbols_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 301
if _libs["repl"].has("drakvuf_free_symbols", "cdecl"):
    drakvuf_free_symbols = _libs["repl"].get("drakvuf_free_symbols", "cdecl")
    drakvuf_free_symbols.argtypes = [POINTER(symbols_t)]
    drakvuf_free_symbols.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 303
if _libs["repl"].has("drakvuf_get_kernel_symbol_rva", "cdecl"):
    drakvuf_get_kernel_symbol_rva = _libs["repl"].get("drakvuf_get_kernel_symbol_rva", "cdecl")
    drakvuf_get_kernel_symbol_rva.argtypes = [drakvuf_t, String, POINTER(addr_t)]
    drakvuf_get_kernel_symbol_rva.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 306
if _libs["repl"].has("drakvuf_get_kernel_struct_size", "cdecl"):
    drakvuf_get_kernel_struct_size = _libs["repl"].get("drakvuf_get_kernel_struct_size", "cdecl")
    drakvuf_get_kernel_struct_size.argtypes = [drakvuf_t, String, POINTER(c_size_t)]
    drakvuf_get_kernel_struct_size.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 309
if _libs["repl"].has("drakvuf_get_kernel_struct_member_rva", "cdecl"):
    drakvuf_get_kernel_struct_member_rva = _libs["repl"].get("drakvuf_get_kernel_struct_member_rva", "cdecl")
    drakvuf_get_kernel_struct_member_rva.argtypes = [drakvuf_t, String, String, POINTER(addr_t)]
    drakvuf_get_kernel_struct_member_rva.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 313
if _libs["repl"].has("drakvuf_get_bitfield_offset_and_size", "cdecl"):
    drakvuf_get_bitfield_offset_and_size = _libs["repl"].get("drakvuf_get_bitfield_offset_and_size", "cdecl")
    drakvuf_get_bitfield_offset_and_size.argtypes = [drakvuf_t, String, String, POINTER(addr_t), POINTER(c_size_t), POINTER(c_size_t)]
    drakvuf_get_bitfield_offset_and_size.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 319
if _libs["repl"].has("json_get_symbol_rva", "cdecl"):
    json_get_symbol_rva = _libs["repl"].get("json_get_symbol_rva", "cdecl")
    json_get_symbol_rva.argtypes = [drakvuf_t, POINTER(json_object), String, POINTER(addr_t)]
    json_get_symbol_rva.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 323
if _libs["repl"].has("json_get_struct_size", "cdecl"):
    json_get_struct_size = _libs["repl"].get("json_get_struct_size", "cdecl")
    json_get_struct_size.argtypes = [drakvuf_t, POINTER(json_object), String, POINTER(c_size_t)]
    json_get_struct_size.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 327
if _libs["repl"].has("json_get_struct_member_rva", "cdecl"):
    json_get_struct_member_rva = _libs["repl"].get("json_get_struct_member_rva", "cdecl")
    json_get_struct_member_rva.argtypes = [drakvuf_t, POINTER(json_object), String, String, POINTER(addr_t)]
    json_get_struct_member_rva.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 333
if _libs["repl"].has("json_get_struct_members_array_rva", "cdecl"):
    json_get_struct_members_array_rva = _libs["repl"].get("json_get_struct_members_array_rva", "cdecl")
    json_get_struct_members_array_rva.argtypes = [drakvuf_t, POINTER(json_object), POINTER(POINTER(c_char) * int(2)), addr_t, POINTER(addr_t)]
    json_get_struct_members_array_rva.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 346
for _lib in _libs.values():
    try:
        vmi = (vmi_instance_t).in_dll(_lib, "vmi")
        break
    except:
        pass

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 347
for _lib in _libs.values():
    try:
        ret = (c_bool).in_dll(_lib, "ret")
        break
    except:
        pass

drakvuf_trap_free_t = CFUNCTYPE(UNCHECKED(None), POINTER(drakvuf_trap_t))# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 354

event_cb_t = CFUNCTYPE(UNCHECKED(None), c_int, POINTER(None))# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 356

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 358
if _libs["repl"].has("drakvuf_init", "cdecl"):
    drakvuf_init = _libs["repl"].get("drakvuf_init", "cdecl")
    drakvuf_init.argtypes = [POINTER(drakvuf_t), String, String, String, c_bool, c_bool, addr_t, c_bool]
    drakvuf_init.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 366
if _libs["repl"].has("drakvuf_close", "cdecl"):
    drakvuf_close = _libs["repl"].get("drakvuf_close", "cdecl")
    drakvuf_close.argtypes = [drakvuf_t, c_bool]
    drakvuf_close.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 367
if _libs["repl"].has("drakvuf_add_trap", "cdecl"):
    drakvuf_add_trap = _libs["repl"].get("drakvuf_add_trap", "cdecl")
    drakvuf_add_trap.argtypes = [drakvuf_t, POINTER(drakvuf_trap_t)]
    drakvuf_add_trap.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 369
if _libs["repl"].has("drakvuf_remove_trap", "cdecl"):
    drakvuf_remove_trap = _libs["repl"].get("drakvuf_remove_trap", "cdecl")
    drakvuf_remove_trap.argtypes = [drakvuf_t, POINTER(drakvuf_trap_t), drakvuf_trap_free_t]
    drakvuf_remove_trap.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 372
if _libs["repl"].has("drakvuf_loop", "cdecl"):
    drakvuf_loop = _libs["repl"].get("drakvuf_loop", "cdecl")
    drakvuf_loop.argtypes = [drakvuf_t]
    drakvuf_loop.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 373
if _libs["repl"].has("drakvuf_interrupt", "cdecl"):
    drakvuf_interrupt = _libs["repl"].get("drakvuf_interrupt", "cdecl")
    drakvuf_interrupt.argtypes = [drakvuf_t, c_int]
    drakvuf_interrupt.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 375
if _libs["repl"].has("drakvuf_is_interrupted", "cdecl"):
    drakvuf_is_interrupted = _libs["repl"].get("drakvuf_is_interrupted", "cdecl")
    drakvuf_is_interrupted.argtypes = [drakvuf_t]
    drakvuf_is_interrupted.restype = c_int

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 376
if _libs["repl"].has("drakvuf_pause", "cdecl"):
    drakvuf_pause = _libs["repl"].get("drakvuf_pause", "cdecl")
    drakvuf_pause.argtypes = [drakvuf_t]
    drakvuf_pause.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 377
if _libs["repl"].has("drakvuf_resume", "cdecl"):
    drakvuf_resume = _libs["repl"].get("drakvuf_resume", "cdecl")
    drakvuf_resume.argtypes = [drakvuf_t]
    drakvuf_resume.restype = None

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 379
if _libs["repl"].has("drakvuf_get_obj_by_handle", "cdecl"):
    drakvuf_get_obj_by_handle = _libs["repl"].get("drakvuf_get_obj_by_handle", "cdecl")
    drakvuf_get_obj_by_handle.argtypes = [drakvuf_t, addr_t, c_uint64]
    drakvuf_get_obj_by_handle.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 383
if _libs["repl"].has("drakvuf_get_os_type", "cdecl"):
    drakvuf_get_os_type = _libs["repl"].get("drakvuf_get_os_type", "cdecl")
    drakvuf_get_os_type.argtypes = [drakvuf_t]
    drakvuf_get_os_type.restype = os_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 384
if _libs["repl"].has("drakvuf_get_page_mode", "cdecl"):
    drakvuf_get_page_mode = _libs["repl"].get("drakvuf_get_page_mode", "cdecl")
    drakvuf_get_page_mode.argtypes = [drakvuf_t]
    drakvuf_get_page_mode.restype = page_mode_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 385
if _libs["repl"].has("drakvuf_get_address_width", "cdecl"):
    drakvuf_get_address_width = _libs["repl"].get("drakvuf_get_address_width", "cdecl")
    drakvuf_get_address_width.argtypes = [drakvuf_t]
    drakvuf_get_address_width.restype = c_int

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 387
if _libs["repl"].has("drakvuf_get_kernel_base", "cdecl"):
    drakvuf_get_kernel_base = _libs["repl"].get("drakvuf_get_kernel_base", "cdecl")
    drakvuf_get_kernel_base.argtypes = [drakvuf_t]
    drakvuf_get_kernel_base.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 389
if _libs["repl"].has("drakvuf_get_current_process", "cdecl"):
    drakvuf_get_current_process = _libs["repl"].get("drakvuf_get_current_process", "cdecl")
    drakvuf_get_current_process.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_get_current_process.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 392
if _libs["repl"].has("drakvuf_get_current_attached_process", "cdecl"):
    drakvuf_get_current_attached_process = _libs["repl"].get("drakvuf_get_current_attached_process", "cdecl")
    drakvuf_get_current_attached_process.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_get_current_attached_process.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 395
if _libs["repl"].has("drakvuf_get_current_thread", "cdecl"):
    drakvuf_get_current_thread = _libs["repl"].get("drakvuf_get_current_thread", "cdecl")
    drakvuf_get_current_thread.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_get_current_thread.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 398
if _libs["repl"].has("drakvuf_get_current_thread_teb", "cdecl"):
    drakvuf_get_current_thread_teb = _libs["repl"].get("drakvuf_get_current_thread_teb", "cdecl")
    drakvuf_get_current_thread_teb.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_get_current_thread_teb.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 401
if _libs["repl"].has("drakvuf_get_current_thread_stackbase", "cdecl"):
    drakvuf_get_current_thread_stackbase = _libs["repl"].get("drakvuf_get_current_thread_stackbase", "cdecl")
    drakvuf_get_current_thread_stackbase.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_get_current_thread_stackbase.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 404
if _libs["repl"].has("drakvuf_get_last_error", "cdecl"):
    drakvuf_get_last_error = _libs["repl"].get("drakvuf_get_last_error", "cdecl")
    drakvuf_get_last_error.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(c_uint32), POINTER(POINTER(c_char))]
    drakvuf_get_last_error.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 410
if _libs["repl"].has("drakvuf_get_process_name", "cdecl"):
    drakvuf_get_process_name = _libs["repl"].get("drakvuf_get_process_name", "cdecl")
    drakvuf_get_process_name.argtypes = [drakvuf_t, addr_t, c_bool]
    if sizeof(c_int) == sizeof(c_void_p):
        drakvuf_get_process_name.restype = ReturnString
    else:
        drakvuf_get_process_name.restype = String
        drakvuf_get_process_name.errcheck = ReturnString

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 415
if _libs["repl"].has("drakvuf_get_process_commandline", "cdecl"):
    drakvuf_get_process_commandline = _libs["repl"].get("drakvuf_get_process_commandline", "cdecl")
    drakvuf_get_process_commandline.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t]
    if sizeof(c_int) == sizeof(c_void_p):
        drakvuf_get_process_commandline.restype = ReturnString
    else:
        drakvuf_get_process_commandline.restype = String
        drakvuf_get_process_commandline.errcheck = ReturnString

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 419
if _libs["repl"].has("drakvuf_get_process_pid", "cdecl"):
    drakvuf_get_process_pid = _libs["repl"].get("drakvuf_get_process_pid", "cdecl")
    drakvuf_get_process_pid.argtypes = [drakvuf_t, addr_t, POINTER(vmi_pid_t)]
    drakvuf_get_process_pid.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 423
if _libs["repl"].has("drakvuf_get_process_thread_id", "cdecl"):
    drakvuf_get_process_thread_id = _libs["repl"].get("drakvuf_get_process_thread_id", "cdecl")
    drakvuf_get_process_thread_id.argtypes = [drakvuf_t, addr_t, POINTER(c_uint32)]
    drakvuf_get_process_thread_id.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 427
if _libs["repl"].has("drakvuf_get_process_dtb", "cdecl"):
    drakvuf_get_process_dtb = _libs["repl"].get("drakvuf_get_process_dtb", "cdecl")
    drakvuf_get_process_dtb.argtypes = [drakvuf_t, addr_t, POINTER(addr_t)]
    drakvuf_get_process_dtb.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 432
if _libs["repl"].has("drakvuf_get_process_userid", "cdecl"):
    drakvuf_get_process_userid = _libs["repl"].get("drakvuf_get_process_userid", "cdecl")
    drakvuf_get_process_userid.argtypes = [drakvuf_t, addr_t]
    drakvuf_get_process_userid.restype = c_int64

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 435
if _libs["repl"].has("drakvuf_get_process_csdversion", "cdecl"):
    drakvuf_get_process_csdversion = _libs["repl"].get("drakvuf_get_process_csdversion", "cdecl")
    drakvuf_get_process_csdversion.argtypes = [drakvuf_t, addr_t]
    drakvuf_get_process_csdversion.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 438
if _libs["repl"].has("drakvuf_get_process_data", "cdecl"):
    drakvuf_get_process_data = _libs["repl"].get("drakvuf_get_process_data", "cdecl")
    drakvuf_get_process_data.argtypes = [drakvuf_t, addr_t, POINTER(proc_data_t)]
    drakvuf_get_process_data.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 454
class struct__mmvad_info(Structure):
    pass

struct__mmvad_info.__slots__ = [
    'starting_vpn',
    'ending_vpn',
    'flags',
    'flags1',
    'file_name_ptr',
    'total_number_of_ptes',
    'prototype_pte',
]
struct__mmvad_info._fields_ = [
    ('starting_vpn', c_uint64),
    ('ending_vpn', c_uint64),
    ('flags', c_uint64),
    ('flags1', c_uint64),
    ('file_name_ptr', addr_t),
    ('total_number_of_ptes', c_uint32),
    ('prototype_pte', addr_t),
]

mmvad_info_t = struct__mmvad_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 454

mmvad_callback = CFUNCTYPE(UNCHECKED(c_bool), drakvuf_t, POINTER(mmvad_info_t), POINTER(None))# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 456

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 458
if _libs["repl"].has("drakvuf_find_mmvad", "cdecl"):
    drakvuf_find_mmvad = _libs["repl"].get("drakvuf_find_mmvad", "cdecl")
    drakvuf_find_mmvad.argtypes = [drakvuf_t, addr_t, addr_t, POINTER(mmvad_info_t)]
    drakvuf_find_mmvad.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 459
if _libs["repl"].has("drakvuf_traverse_mmvad", "cdecl"):
    drakvuf_traverse_mmvad = _libs["repl"].get("drakvuf_traverse_mmvad", "cdecl")
    drakvuf_traverse_mmvad.argtypes = [drakvuf_t, addr_t, mmvad_callback, POINTER(None)]
    drakvuf_traverse_mmvad.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 460
if _libs["repl"].has("drakvuf_is_mmvad_commited", "cdecl"):
    drakvuf_is_mmvad_commited = _libs["repl"].get("drakvuf_is_mmvad_commited", "cdecl")
    drakvuf_is_mmvad_commited.argtypes = [drakvuf_t, POINTER(mmvad_info_t)]
    drakvuf_is_mmvad_commited.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 461
if _libs["repl"].has("drakvuf_mmvad_type", "cdecl"):
    drakvuf_mmvad_type = _libs["repl"].get("drakvuf_mmvad_type", "cdecl")
    drakvuf_mmvad_type.argtypes = [drakvuf_t, POINTER(mmvad_info_t)]
    drakvuf_mmvad_type.restype = c_uint32

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 462
if _libs["repl"].has("drakvuf_mmvad_commit_charge", "cdecl"):
    drakvuf_mmvad_commit_charge = _libs["repl"].get("drakvuf_mmvad_commit_charge", "cdecl")
    drakvuf_mmvad_commit_charge.argtypes = [drakvuf_t, POINTER(mmvad_info_t), POINTER(c_uint64)]
    drakvuf_mmvad_commit_charge.restype = c_uint64

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 464
if _libs["repl"].has("drakvuf_get_wow_peb", "cdecl"):
    drakvuf_get_wow_peb = _libs["repl"].get("drakvuf_get_wow_peb", "cdecl")
    drakvuf_get_wow_peb.argtypes = [drakvuf_t, POINTER(access_context_t), addr_t]
    drakvuf_get_wow_peb.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 465
if _libs["repl"].has("drakvuf_get_wow_context", "cdecl"):
    drakvuf_get_wow_context = _libs["repl"].get("drakvuf_get_wow_context", "cdecl")
    drakvuf_get_wow_context.argtypes = [drakvuf_t, addr_t, POINTER(addr_t)]
    drakvuf_get_wow_context.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 466
if _libs["repl"].has("drakvuf_get_user_stack32", "cdecl"):
    drakvuf_get_user_stack32 = _libs["repl"].get("drakvuf_get_user_stack32", "cdecl")
    drakvuf_get_user_stack32.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(addr_t), POINTER(addr_t)]
    drakvuf_get_user_stack32.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 467
if _libs["repl"].has("drakvuf_get_user_stack64", "cdecl"):
    drakvuf_get_user_stack64 = _libs["repl"].get("drakvuf_get_user_stack64", "cdecl")
    drakvuf_get_user_stack64.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(addr_t)]
    drakvuf_get_user_stack64.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 469
if _libs["repl"].has("drakvuf_get_current_thread_id", "cdecl"):
    drakvuf_get_current_thread_id = _libs["repl"].get("drakvuf_get_current_thread_id", "cdecl")
    drakvuf_get_current_thread_id.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(c_uint32)]
    drakvuf_get_current_thread_id.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 473
if _libs["repl"].has("drakvuf_exportksym_to_va", "cdecl"):
    drakvuf_exportksym_to_va = _libs["repl"].get("drakvuf_exportksym_to_va", "cdecl")
    drakvuf_exportksym_to_va.argtypes = [drakvuf_t, vmi_pid_t, String, String, addr_t]
    drakvuf_exportksym_to_va.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 477
if _libs["repl"].has("drakvuf_exportsym_to_va", "cdecl"):
    drakvuf_exportsym_to_va = _libs["repl"].get("drakvuf_exportsym_to_va", "cdecl")
    drakvuf_exportsym_to_va.argtypes = [drakvuf_t, addr_t, String, String]
    drakvuf_exportsym_to_va.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 480
if _libs["repl"].has("drakvuf_export_lib_address", "cdecl"):
    drakvuf_export_lib_address = _libs["repl"].get("drakvuf_export_lib_address", "cdecl")
    drakvuf_export_lib_address.argtypes = [drakvuf_t, addr_t, String]
    drakvuf_export_lib_address.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 484
if _libs["repl"].has("drakvuf_get_current_thread_previous_mode", "cdecl"):
    drakvuf_get_current_thread_previous_mode = _libs["repl"].get("drakvuf_get_current_thread_previous_mode", "cdecl")
    drakvuf_get_current_thread_previous_mode.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(privilege_mode_t)]
    drakvuf_get_current_thread_previous_mode.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 488
if _libs["repl"].has("drakvuf_get_thread_previous_mode", "cdecl"):
    drakvuf_get_thread_previous_mode = _libs["repl"].get("drakvuf_get_thread_previous_mode", "cdecl")
    drakvuf_get_thread_previous_mode.argtypes = [drakvuf_t, addr_t, POINTER(privilege_mode_t)]
    drakvuf_get_thread_previous_mode.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 492
if _libs["repl"].has("drakvuf_is_thread", "cdecl"):
    drakvuf_is_thread = _libs["repl"].get("drakvuf_is_thread", "cdecl")
    drakvuf_is_thread.argtypes = [drakvuf_t, addr_t, addr_t]
    drakvuf_is_thread.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 496
if _libs["repl"].has("drakvuf_is_process", "cdecl"):
    drakvuf_is_process = _libs["repl"].get("drakvuf_is_process", "cdecl")
    drakvuf_is_process.argtypes = [drakvuf_t, addr_t, addr_t]
    drakvuf_is_process.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 500
if _libs["repl"].has("drakvuf_find_process", "cdecl"):
    drakvuf_find_process = _libs["repl"].get("drakvuf_find_process", "cdecl")
    drakvuf_find_process.argtypes = [drakvuf_t, vmi_pid_t, String, POINTER(addr_t)]
    drakvuf_find_process.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 515
class struct__module_info(Structure):
    pass

struct__module_info.__slots__ = [
    'eprocess_addr',
    'dtb',
    'pid',
    'base_addr',
    'full_name',
    'base_name',
    'is_wow',
    'is_wow_process',
]
struct__module_info._fields_ = [
    ('eprocess_addr', addr_t),
    ('dtb', addr_t),
    ('pid', vmi_pid_t),
    ('base_addr', addr_t),
    ('full_name', POINTER(unicode_string_t)),
    ('base_name', POINTER(unicode_string_t)),
    ('is_wow', c_bool),
    ('is_wow_process', c_bool),
]

module_info_t = struct__module_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 515

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 517
if _libs["repl"].has("drakvuf_enumerate_processes", "cdecl"):
    drakvuf_enumerate_processes = _libs["repl"].get("drakvuf_enumerate_processes", "cdecl")
    drakvuf_enumerate_processes.argtypes = [drakvuf_t, CFUNCTYPE(UNCHECKED(None), drakvuf_t, addr_t, POINTER(None)), POINTER(None)]
    drakvuf_enumerate_processes.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 521
if _libs["repl"].has("drakvuf_enumerate_processes_with_module", "cdecl"):
    drakvuf_enumerate_processes_with_module = _libs["repl"].get("drakvuf_enumerate_processes_with_module", "cdecl")
    drakvuf_enumerate_processes_with_module.argtypes = [drakvuf_t, String, CFUNCTYPE(UNCHECKED(c_bool), drakvuf_t, POINTER(module_info_t), POINTER(None)), POINTER(None)]
    drakvuf_enumerate_processes_with_module.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 526
if _libs["repl"].has("drakvuf_is_crashreporter", "cdecl"):
    drakvuf_is_crashreporter = _libs["repl"].get("drakvuf_is_crashreporter", "cdecl")
    drakvuf_is_crashreporter.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), POINTER(vmi_pid_t)]
    drakvuf_is_crashreporter.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 530
if _libs["repl"].has("drakvuf_get_module_list", "cdecl"):
    drakvuf_get_module_list = _libs["repl"].get("drakvuf_get_module_list", "cdecl")
    drakvuf_get_module_list.argtypes = [drakvuf_t, addr_t, POINTER(addr_t)]
    drakvuf_get_module_list.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 534
if _libs["repl"].has("drakvuf_get_module_list_wow", "cdecl"):
    drakvuf_get_module_list_wow = _libs["repl"].get("drakvuf_get_module_list_wow", "cdecl")
    drakvuf_get_module_list_wow.argtypes = [drakvuf_t, POINTER(access_context_t), addr_t, POINTER(addr_t)]
    drakvuf_get_module_list_wow.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 540
if _libs["repl"].has("drakvuf_obj_ref_by_handle", "cdecl"):
    drakvuf_obj_ref_by_handle = _libs["repl"].get("drakvuf_obj_ref_by_handle", "cdecl")
    drakvuf_obj_ref_by_handle.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t, addr_t, object_manager_object_t, POINTER(addr_t)]
    drakvuf_obj_ref_by_handle.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 548
if _libs["repl"].has("drakvuf_read_ascii_str", "cdecl"):
    drakvuf_read_ascii_str = _libs["repl"].get("drakvuf_read_ascii_str", "cdecl")
    drakvuf_read_ascii_str.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t]
    if sizeof(c_int) == sizeof(c_void_p):
        drakvuf_read_ascii_str.restype = ReturnString
    else:
        drakvuf_read_ascii_str.restype = String
        drakvuf_read_ascii_str.errcheck = ReturnString

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 550
if _libs["repl"].has("drakvuf_read_unicode_common", "cdecl"):
    drakvuf_read_unicode_common = _libs["repl"].get("drakvuf_read_unicode_common", "cdecl")
    drakvuf_read_unicode_common.argtypes = [vmi_instance_t, POINTER(access_context_t)]
    drakvuf_read_unicode_common.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 552
if _libs["repl"].has("drakvuf_read_unicode", "cdecl"):
    drakvuf_read_unicode = _libs["repl"].get("drakvuf_read_unicode", "cdecl")
    drakvuf_read_unicode.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t]
    drakvuf_read_unicode.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 554
if _libs["repl"].has("drakvuf_read_unicode_va", "cdecl"):
    drakvuf_read_unicode_va = _libs["repl"].get("drakvuf_read_unicode_va", "cdecl")
    drakvuf_read_unicode_va.argtypes = [vmi_instance_t, addr_t, vmi_pid_t]
    drakvuf_read_unicode_va.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 556
if _libs["repl"].has("drakvuf_read_unicode32_common", "cdecl"):
    drakvuf_read_unicode32_common = _libs["repl"].get("drakvuf_read_unicode32_common", "cdecl")
    drakvuf_read_unicode32_common.argtypes = [vmi_instance_t, POINTER(access_context_t)]
    drakvuf_read_unicode32_common.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 558
if _libs["repl"].has("drakvuf_read_unicode32", "cdecl"):
    drakvuf_read_unicode32 = _libs["repl"].get("drakvuf_read_unicode32", "cdecl")
    drakvuf_read_unicode32.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t]
    drakvuf_read_unicode32.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 560
if _libs["repl"].has("drakvuf_read_unicode32_va", "cdecl"):
    drakvuf_read_unicode32_va = _libs["repl"].get("drakvuf_read_unicode32_va", "cdecl")
    drakvuf_read_unicode32_va.argtypes = [vmi_instance_t, addr_t, vmi_pid_t]
    drakvuf_read_unicode32_va.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 562
if _libs["repl"].has("drakvuf_get_module_base_addr", "cdecl"):
    drakvuf_get_module_base_addr = _libs["repl"].get("drakvuf_get_module_base_addr", "cdecl")
    drakvuf_get_module_base_addr.argtypes = [drakvuf_t, addr_t, String, POINTER(addr_t)]
    drakvuf_get_module_base_addr.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 567
if _libs["repl"].has("drakvuf_get_module_base_addr_ctx", "cdecl"):
    drakvuf_get_module_base_addr_ctx = _libs["repl"].get("drakvuf_get_module_base_addr_ctx", "cdecl")
    drakvuf_get_module_base_addr_ctx.argtypes = [drakvuf_t, addr_t, POINTER(access_context_t), String, POINTER(addr_t)]
    drakvuf_get_module_base_addr_ctx.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 573
if _libs["repl"].has("drakvuf_get_process_ppid", "cdecl"):
    drakvuf_get_process_ppid = _libs["repl"].get("drakvuf_get_process_ppid", "cdecl")
    drakvuf_get_process_ppid.argtypes = [drakvuf_t, addr_t, POINTER(vmi_pid_t)]
    drakvuf_get_process_ppid.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 577
if _libs["repl"].has("drakvuf_reg_keyhandle_path", "cdecl"):
    drakvuf_reg_keyhandle_path = _libs["repl"].get("drakvuf_reg_keyhandle_path", "cdecl")
    drakvuf_reg_keyhandle_path.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), c_uint64]
    drakvuf_reg_keyhandle_path.restype = POINTER(gchar)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 581
if _libs["repl"].has("drakvuf_get_filename_from_handle", "cdecl"):
    drakvuf_get_filename_from_handle = _libs["repl"].get("drakvuf_get_filename_from_handle", "cdecl")
    drakvuf_get_filename_from_handle.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t]
    if sizeof(c_int) == sizeof(c_void_p):
        drakvuf_get_filename_from_handle.restype = ReturnString
    else:
        drakvuf_get_filename_from_handle.restype = String
        drakvuf_get_filename_from_handle.errcheck = ReturnString

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 586
if _libs["repl"].has("drakvuf_read_wchar_array", "cdecl"):
    drakvuf_read_wchar_array = _libs["repl"].get("drakvuf_read_wchar_array", "cdecl")
    drakvuf_read_wchar_array.argtypes = [vmi_instance_t, POINTER(access_context_t), c_size_t]
    drakvuf_read_wchar_array.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 590
if _libs["repl"].has("drakvuf_wchar_string_length", "cdecl"):
    drakvuf_wchar_string_length = _libs["repl"].get("drakvuf_wchar_string_length", "cdecl")
    drakvuf_wchar_string_length.argtypes = [vmi_instance_t, POINTER(access_context_t)]
    drakvuf_wchar_string_length.restype = c_size_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 593
if _libs["repl"].has("drakvuf_read_wchar_string", "cdecl"):
    drakvuf_read_wchar_string = _libs["repl"].get("drakvuf_read_wchar_string", "cdecl")
    drakvuf_read_wchar_string.argtypes = [vmi_instance_t, POINTER(access_context_t)]
    drakvuf_read_wchar_string.restype = POINTER(unicode_string_t)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 596
if _libs["repl"].has("drakvuf_escape_str", "cdecl"):
    drakvuf_escape_str = _libs["repl"].get("drakvuf_escape_str", "cdecl")
    drakvuf_escape_str.argtypes = [String]
    drakvuf_escape_str.restype = POINTER(gchar)

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 598
if _libs["repl"].has("drakvuf_is_wow64", "cdecl"):
    drakvuf_is_wow64 = _libs["repl"].get("drakvuf_is_wow64", "cdecl")
    drakvuf_is_wow64.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t)]
    drakvuf_is_wow64.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 600
if _libs["repl"].has("drakvuf_get_function_argument", "cdecl"):
    drakvuf_get_function_argument = _libs["repl"].get("drakvuf_get_function_argument", "cdecl")
    drakvuf_get_function_argument.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), c_int]
    drakvuf_get_function_argument.restype = addr_t

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 604
if _libs["repl"].has("drakvuf_get_pid_from_handle", "cdecl"):
    drakvuf_get_pid_from_handle = _libs["repl"].get("drakvuf_get_pid_from_handle", "cdecl")
    drakvuf_get_pid_from_handle.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t, POINTER(vmi_pid_t)]
    drakvuf_get_pid_from_handle.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 605
if _libs["repl"].has("drakvuf_get_tid_from_handle", "cdecl"):
    drakvuf_get_tid_from_handle = _libs["repl"].get("drakvuf_get_tid_from_handle", "cdecl")
    drakvuf_get_tid_from_handle.argtypes = [drakvuf_t, POINTER(drakvuf_trap_info_t), addr_t, POINTER(c_uint32)]
    drakvuf_get_tid_from_handle.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 607
if _libs["repl"].has("drakvuf_set_vcpu_gprs", "cdecl"):
    drakvuf_set_vcpu_gprs = _libs["repl"].get("drakvuf_set_vcpu_gprs", "cdecl")
    drakvuf_set_vcpu_gprs.argtypes = [drakvuf_t, c_int, POINTER(registers_t)]
    drakvuf_set_vcpu_gprs.restype = c_bool

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 613
if _libs["repl"].has("drakvuf_event_fd_add", "cdecl"):
    drakvuf_event_fd_add = _libs["repl"].get("drakvuf_event_fd_add", "cdecl")
    drakvuf_event_fd_add.argtypes = [drakvuf_t, c_int, event_cb_t, POINTER(None)]
    drakvuf_event_fd_add.restype = c_int

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 618
if _libs["repl"].has("drakvuf_event_fd_remove", "cdecl"):
    drakvuf_event_fd_remove = _libs["repl"].get("drakvuf_event_fd_remove", "cdecl")
    drakvuf_event_fd_remove.argtypes = [drakvuf_t, c_int]
    drakvuf_event_fd_remove.restype = c_int

enum_anon_166 = c_int# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

OUTPUT_DEFAULT = 0# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

OUTPUT_CSV = (OUTPUT_DEFAULT + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

OUTPUT_KV = (OUTPUT_CSV + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

OUTPUT_JSON = (OUTPUT_KV + 1)# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

output_format_t = enum_anon_166# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 631

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 126
def NUMBER_OF(x):
    return (sizeof(x) / sizeof((x [0])))

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 133
try:
    SIGDRAKVUFERROR = (-1)
except:
    pass

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 134
try:
    SIGDRAKVUFTIMEOUT = (-2)
except:
    pass

# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 135
try:
    SIGDRAKVUFCRASH = (-3)
except:
    pass

process_data = struct_process_data# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 179

drakvuf = struct_drakvuf# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 181

drakvuf_trap = struct_drakvuf_trap# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 202

drakvuf_trap_info = struct_drakvuf_trap_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 200

symbol = struct_symbol# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 288

symbols = struct_symbols# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 295

_mmvad_info = struct__mmvad_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 454

_module_info = struct__module_info# /shared/drakvuf/src/libdrakvuf/libdrakvuf.h: 515

# No inserted files

# No prefix-stripping

