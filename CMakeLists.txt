cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro)

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set (BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Dependencies
include (${CMAKE_CURRENT_SOURCE_DIR}/cmake/BuildBinutils.cmake)

find_package (LibElf REQUIRED)
find_package (LibCapstone)
find_package (PkgConfig REQUIRED)

set (PROJECT_VERSION_MAJOR  3)
set (PROJECT_VERSION_MINOR  0)
set (PROJECT_VERSION_PATCH  0)
set (PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

if(LIBCAPSTONE_FOUND)
	set (CAPSTONE_SRCS
		src/capstone-disassembly.cc
	)
else()
  set(LIBCAPSTONE_INCLUDE_DIRS "")
  set(LIBCAPSTONE_LIBRARIES "")
endif()

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

pkg_check_modules(GTKMM REQUIRED gtkmm-3.0)
pkg_check_modules(GTKSOURCEVIEWMM REQUIRED gtksourceviewmm-3.0)
pkg_check_modules(LIBXMLPP REQUIRED libxml++-2.6)
pkg_check_modules(LIBCURL REQUIRED libcurl)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1 -pthread")
LINK_DIRECTORIES(
	${CMAKE_BINARY_DIR}/install-binutils/lib ${CMAKE_BINARY_DIR}/install-binutils/lib64
	${CMAKE_BINARY_DIR}/binutils/libiberty
	)

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE release)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/server)

add_executable (file-to-source
	src/utils.cc
	tools/file-to-source.cc
)

add_custom_command (OUTPUT emilpro_glade.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/emilpro_glade.hh glade_file ${CMAKE_SOURCE_DIR}/src/gtk/emilpro.glade 
  DEPENDS ${CMAKE_SOURCE_DIR}/src/gtk/emilpro.glade file-to-source
)


add_custom_command (OUTPUT built_in_instruction_models.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh built_in_instruction_models_xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/arm.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/avr.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/i386.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/mips.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/powerpc.xml
  DEPENDS
    ${CMAKE_SOURCE_DIR}/data/instruction-models/arm.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/avr.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/i386.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/mips.xml
    ${CMAKE_SOURCE_DIR}/data/instruction-models/powerpc.xml
  	file-to-source
)

add_custom_target(emilpro_built_in_instruction_models ALL
	DEPENDS built_in_instruction_models.hh
)

set (BASE_SRCS
	src/addresshistory.cc
	src/architecturefactory.cc
	src/bfd-disassembly.cc
	src/bfd-provider.cc
	${CAPSTONE_SRCS}
	src/configuration.cc
	src/emilpro.cc
	src/instructionfactory.cc
	src/jumptargetdisplay.cc
	src/model.cc
	src/namemangler.cc
	src/network-listener.cc
	src/preferences.cc
	src/server-connection.cc
	src/symbolfactory.cc
	src/utils.cc
	src/xmlfactory.cc
	src/xmlstring.cc
	)
	
set (GUI_SRCS
	src/gtk/hexview.cc
	src/gtk/infobox.cc
	src/gtk/instructionview.cc
	src/gtk/main.cc
	src/gtk/sourceview.cc
	src/gtk/symbolview.cc
	src/ui-helpers.cc
	)
	
set_property(SOURCE src/gtk/main.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/emilpro_glade.hh)
set_property(SOURCE src/emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

include_directories(
	${CMAKE_BINARY_DIR}/install-binutils/include/
	src/gtk/include/
	src/include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${GTKMM_INCLUDE_DIRS}
	${GTKSOURCEVIEWMM_INCLUDE_DIRS}
	${LIBXMLPP_INCLUDE_DIRS}
	${LIBCURL_INCLUDE_DIRS}
	${LibGeoIP_INCLUDE_DIR}
	${LIBCAPSTONE_INCLUDE_DIRS}
	)

add_executable (emilpro
	${BASE_SRCS}
	${GUI_SRCS}
	)

add_executable (tools/squash-instruction-models
	${BASE_SRCS}
	tools/squash-instruction-models.cc
	)

add_dependencies(emilpro binutils)
add_dependencies(tools/squash-instruction-models binutils)

set (BASE_LIBS
	${LIBELF_LIBRARIES}
	opcodes
	bfd
	iberty
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	pthread
	dl
	${LIBCAPSTONE_LIBRARIES}
	)

target_link_libraries(emilpro
	${GTKMM_LIBRARIES}
	${GTKSOURCEVIEWMM_LIBRARIES}
	${BASE_LIBS}
	)

target_link_libraries(tools/squash-instruction-models
	${BASE_LIBS}
	)

install(TARGETS emilpro RUNTIME DESTINATION bin)