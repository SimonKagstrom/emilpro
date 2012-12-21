# - Try to find binutils
# Once done this will define
#
#  LIBBFD_FOUND - system has libbfd
#  LIBBFD_INCLUDE_DIRS - the libbfd include directory
#  LIBBFD_LIBRARIES - Link these to use libbfd
#  LIBBFD_DEFINITIONS - Compiler switches required for using libbfd
#

find_path (LIBBFD_INCLUDE_DIRS
    NAMES
      bfd.h
    HINTS
      /home/simkag/local/include
      /home/ska/local/include
    PATHS
      /opt/local/include
      /home/simkag/local/include
      /home/ska/local/include
      ENV CPATH) # PATH and INCLUDE will also work

set (LIB_HINTS
      /home/simkag/local/lib
      /home/ska/local/lib
)

set (LIB_PATHS
      /opt/local/lib
      /home/simkag/local/lib
      /home/ska/local/lib
      ENV LIBRARY_PATH   # PATH and LIB will also work
      ENV LD_LIBRARY_PATH
)

find_library (BFD_LIB
    NAMES bfd HINTS ${LIB_HINTS} PATHS ${LIB_PATHS})

find_library (OPCODES_LIB
    NAMES opcodes HINTS ${LIB_HINTS} PATHS ${LIB_PATHS})

find_library (IBERTY_LIB
    NAMES iberty HINTS ${LIB_HINTS} PATHS ${LIB_PATHS})

include (FindPackageHandleStandardArgs)

set(LIBBFD_LIBRARIES
    ${BFD_LIB} ${OPCODES_LIB} ${IBERTY_LIB})


# handle the QUIETLY and REQUIRED arguments and set LIBBFD_FOUND to TRUE
# if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBfd DEFAULT_MSG
    LIBBFD_LIBRARIES
    LIBBFD_INCLUDE_DIRS)

mark_as_advanced(LIBDW_INCLUDE_DIR BFD_INCLUDE_DIR)
mark_as_advanced(LIBBFD_INCLUDE_DIRS LIBBFD_LIBRARIES)
