# Try to find Xen headers
# Xen_FOUND
# Xen_INCLUDE_DIRS

# define HAVE_XXX
include(CheckIncludeFile)
check_include_file(xenctrl.h HAVE_XENCTRL_H)
check_include_file(libxl_utils.h HAVE_XENLIGHT_H)

find_path(Xen_INCLUDE_DIR
    NAMES xenctrl.h libxl_utils.h)

find_library(Xenctrl_LIBRARY
             NAMES xenctrl)

find_library(XenLight_LIBRARY
             NAMES xenlight)

find_library(Xentoollog_LIBRARY
             NAMES xentoollog)

# A workaround for Ubuntu 16.04 used in Travis-CI because of broken symlink
if (XL_VERSION)
    find_library(Xlutil_LIBRARY
                NAMES ${XL_VERSION})
else()
    find_library(Xlutil_LIBRARY
                 NAMES xlutil)
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xen
    DEFAULT_MSG
    Xen_INCLUDE_DIR Xenctrl_LIBRARY XenLight_LIBRARY Xlutil_LIBRARY)

if (Xen_FOUND)
    set(Xen_INCLUDE_DIRS ${Xen_INCLUDE_DIR})
    set(Xen_LIBRARIES ${Xenctrl_LIBRARY} ${XenLight_LIBRARY} ${Xlutil_LIBRARY})
    if (Xentoollog_LIBRARY)
        set(Xen_LIBRARIES ${Xen_LIBRARIES} ${Xentoollog_LIBRARY})
    endif()
endif ()

mark_as_advanced(Xen_INCLUDE_DIR)
