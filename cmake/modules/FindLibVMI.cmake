# Try to find Xen headers
# LibVMI_FOUND
# LibVMI_INCLUDE_DIRS

# define HAVE_XXX
set(CMAKE_REQUIRED_INCLUDES "/usr/local/include/libvmi")

include(CheckIncludeFile)
check_include_file(libvmi.h HAVE_LIBVMI_H)

find_path(LibVMI_INCLUDE_DIR
    NAMES libvmi.h
    PATHS "/usr/local/include/libvmi")

find_library(LibVMI_LIBRARY
             NAMES libvmi.so
             HINTS "/usr/local/lib")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibVMI
    DEFAULT_MSG
    LibVMI_INCLUDE_DIR LibVMI_LIBRARY)

if (LibVMI_FOUND)
    set(LibVMI_INCLUDE_DIRS ${LibVMI_INCLUDE_DIR})
endif ()

mark_as_advanced(LibVMI_INCLUDE_DIR)
