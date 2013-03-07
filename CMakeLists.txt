cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro)


set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Dependencies
find_package (LibElf REQUIRED)
find_package (LibDwarf REQUIRED)
find_package (LibBfd REQUIRED)
find_package (PkgConfig REQUIRED)

set (PROJECT_VERSION_MAJOR  1)
set (PROJECT_VERSION_MINOR  0)
set (PROJECT_VERSION_PATCH  0)
set (PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

pkg_check_modules(GTKMM gtkmm-3.0)
pkg_check_modules(GTKSOURCEVIEWMM gtksourceviewmm-3.0)
pkg_check_modules(LIBXMLPP libxml++-2.6)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (TGT emilpro)

set (CMAKE_BUILD_TYPE debug)

set (${TGT}_SRCS
	src/architecturefactory.cc
	src/bfd-disassembly.cc
	src/bfd-provider.cc
	src/instructionfactory.cc
	src/jumptargetdisplay.cc
	src/model.cc
	src/symbolfactory.cc
	src/utils.cc
	src/xmlfactory.cc
	src/gtk/hexview.cc
	src/gtk/main.cc
	)

include_directories(
	src/gtk/include/
	src/include/
	${LIBELF_INCLUDE_DIRS}
	${LIBDWARF_INCLUDE_DIRS}
	${LIBBFD_INCLUDE_DIRS}
	${GTKMM_INCLUDE_DIRS}
	${GTKSOURCEVIEWMM_INCLUDE_DIRS}
	${LIBXMLPP_INCLUDE_DIRS}
	)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	${LIBDWARF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${GTKMM_LIBRARIES}
	${GTKSOURCEVIEWMM_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	z
	)
