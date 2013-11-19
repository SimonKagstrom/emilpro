cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro-server)

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)
set (BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Dependencies
include (${CMAKE_CURRENT_SOURCE_DIR}/../cmake/BuildBinutils.cmake)

find_package (LibElf REQUIRED)
find_package (LibGeoIP REQUIRED)
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
pkg_check_modules(LIBCURL libcurl)
pkg_check_modules(CGICC cgicc)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE release)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/server)

add_executable (file-to-source
	../src/utils.cc
	../tools/file-to-source.cc
)


set (BASE_SRCS
	../src/addresshistory.cc
	../src/architecturefactory.cc
	../src/null-disassembly.cc
	../src/null-provider.cc
	../src/configuration.cc
	../src/emilpro.cc
	../src/instructionfactory.cc
	../src/jumptargetdisplay.cc
	../src/model.cc
	../src/namemangler.cc
	../src/network-listener.cc
	../src/preferences.cc
	../src/server-connection.cc
	../src/symbolfactory.cc
	../src/utils.cc
	../src/xmlfactory.cc
	../src/xmlstring.cc
	)

set_property(SOURCE ../src/emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

include_directories(
	../src/gtk/include/
	../src/include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${CMAKE_BINARY_DIR}/install-binutils/include/
	${LIBXMLPP_INCLUDE_DIRS}
	${LIBCURL_INCLUDE_DIRS}
	${LibGeoIP_INCLUDE_DIR}
	)

add_executable (tools/test-remote-communication
	${BASE_SRCS}
	../tools/test-remote-communication.cc
	)

add_executable (server/cgi-server
	${BASE_SRCS}
	../src/server/cgi-server.cc
	../src/server/html-generator.cc
	../tools/cgi-server-main.cc
	)

add_executable (server/cgi-handler
	../src/utils.cc
	../tools/cgi-handler.cc
	)

set_property(TARGET tools/test-remote-communication APPEND PROPERTY OBJECT_DEPENDS binutils)
set_property(TARGET server/cgi-server APPEND PROPERTY OBJECT_DEPENDS binutils)

set (BASE_LIBS
	${LIBELF_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)

target_link_libraries(tools/test-remote-communication
	${BASE_LIBS}
	)

target_link_libraries(server/cgi-server
	${BASE_LIBS}
	${LibGeoIP_LIBRARY}
	)

target_link_libraries(server/cgi-handler
	${CGICC_LIBRARIES}
	)

add_custom_command (OUTPUT tools/setup-conf-dir.sh
  COMMAND cp ${CMAKE_SOURCE_DIR}/../tools/setup-conf-dir.sh ${CMAKE_BINARY_DIR}/tools/setup-conf-dir.sh
  DEPENDS
	${CMAKE_SOURCE_DIR}/../tools/setup-conf-dir.sh
)

add_custom_target(setup_conf_dir ALL
	DEPENDS tools/setup-conf-dir.sh
)
