# - Try to find libudis
# Once done this will define
#
#  LIBOPDIS_FOUND - system has libudis86
#  LIBOPDIS_INCLUDE_DIRS - the libudis86 include directory
#  LIBOPDIS_LIBRARIES - Link these to use libudis86
#  LIBOPDIS_DEFINITIONS - Compiler switches required for using libudis86
#
# Based on:
#
#  Copyright (c) 2008 Bernhard Walle <bernhard.walle@gmx.de>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (LIBOPDIS_LIBRARIES AND LIBOPDIS_INCLUDE_DIRS)
  set (LibOPDIS_FIND_QUIETLY TRUE)
endif (LIBOPDIS_LIBRARIES AND LIBOPDIS_INCLUDE_DIRS)

find_path (LIBOPDIS_INCLUDE_DIRS
    NAMES
      opdis/opdis.h
    PATHS
      /usr/include
      /usr/include/udis86
      /usr/local/include
      /usr/local/include/udis86
      /opt/local/include
      /opt/local/include/udis86
      /home/simkag/local/include
      /home/ska/local/include
      ENV CPATH)

find_library (LIBOPDIS_LIBRARIES
    NAMES
      opdis
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /home/simkag/local/lib
      /home/ska/local/lib
      ENV LIBRARY_PATH
      ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBOPDIS_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibOPDIS DEFAULT_MSG
    LIBOPDIS_LIBRARIES
    LIBOPDIS_INCLUDE_DIRS)


mark_as_advanced(LIBOPDIS_INCLUDE_DIRS LIBOPDIS_LIBRARIES)
