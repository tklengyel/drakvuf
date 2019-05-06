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
             NAMES libxenctrl.so)

find_library(Xentoollog_LIBRARY
             NAMES libxentoollog.so)

find_library(XL_LIBRARY
             NAMES libxlutil.so)

find_library(XenLight_LIBRARY
             NAMES libxenlight.so)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Xen
    DEFAULT_MSG
    Xen_INCLUDE_DIR Xenctrl_LIBRARY Xentoollog_LIBRARY XL_LIBRARY)

if (Xen_FOUND)
    set(Xen_INCLUDE_DIRS ${Xen_INCLUDE_DIR})
    set(Xenctrl_LIBRARIES ${Xenctrl_LIBRARY} ${Xentoollog_LIBRARY} ${XL_LIBRARY} ${XenLight_LIBRARY})
endif ()

mark_as_advanced(Xen_INCLUDE_DIR)
