# - Try to find libcapstone
# Once done this will define
#
#  LIBCAPSTONE_FOUND - system has libcapstone
#  LIBCAPSTONE_INCLUDE_DIRS - the libcapstone include directory
#  LIBCAPSTONE_LIBRARIES - Link these to use libcapstone
#  LIBCAPSTONE_DEFINITIONS - Compiler switches required for using libcapstone
#

if (LIBCAPSTONE_LIBRARIES AND LIBCAPSTONE_INCLUDE_DIRS)
  set (LibCapstone_FIND_QUIETLY TRUE)
endif ()

find_path (CAPSTONE_INCLUDE_DIR
    NAMES
      capstone/capstone.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      /home/ska/local/include
      ENV CPATH) # PATH and INCLUDE will also work
if (CAPSTONE_INCLUDE_DIR)
    set (LIBCAPSTONE_INCLUDE_DIRS  ${CAPSTONE_INCLUDE_DIR})
endif ()

find_library (LIBCAPSTONE_LIBRARIES
    NAMES
      capstone
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      /home/ska/local/lib
      ENV LIBRARY_PATH   # PATH and LIB will also work
      ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBCAPSTONE_FOUND to TRUE
# if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibCapstone DEFAULT_MSG
    LIBCAPSTONE_LIBRARIES
    LIBCAPSTONE_INCLUDE_DIRS)

mark_as_advanced(LIBCAPSTONE_INCLUDE_DIRS LIBCAPSTONE_LIBRARIES)
