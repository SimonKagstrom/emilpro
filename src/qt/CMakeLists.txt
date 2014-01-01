cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro)

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

set (BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Dependencies
include (${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/BuildBinutils.cmake)

find_package (LibElf REQUIRED)
find_package (PkgConfig REQUIRED)
find_package(Qt5Widgets REQUIRED)

set (PROJECT_VERSION_MAJOR  3)
set (PROJECT_VERSION_MINOR  0)
set (PROJECT_VERSION_PATCH  0)
set (PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

pkg_check_modules(LIBXMLPP libxml++-2.6)
pkg_check_modules(LIBCURL libcurl)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1 ${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/install-binutils/lib ${CMAKE_BINARY_DIR}/install-binutils/lib64)

set (CMAKE_BUILD_TYPE debug)
set(CMAKE_AUTOMOC ON)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/server)

add_executable (file-to-source
	../utils.cc
	../../tools/file-to-source.cc
)


add_custom_command (OUTPUT built_in_instruction_models.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh built_in_instruction_models_xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/arm.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/avr.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/i386.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/mips.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/powerpc.xml
  DEPENDS
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/arm.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/avr.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/i386.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/mips.xml
    ${CMAKE_SOURCE_DIR}/../../data/instruction-models/powerpc.xml
  	file-to-source
)

add_custom_target(emilpro_built_in_instruction_models ALL
	DEPENDS built_in_instruction_models.hh
)

set (BASE_SRCS
	../addresshistory.cc
	../architecturefactory.cc
	../bfd-disassembly.cc
	../bfd-provider.cc
	../configuration.cc
	../emilpro.cc
	../instructionfactory.cc
	../jumptargetdisplay.cc
	../model.cc
	../namemangler.cc
	../network-listener.cc
	../preferences.cc
	../server-connection.cc
	../symbolfactory.cc
	../ui-helpers.cc
	../utils.cc
	../xmlfactory.cc
	../xmlstring.cc
	)

set (GUI_SRCS
	emilpro/highlighter.cpp
	emilpro/jumpdisplay-delegate.cpp
	emilpro/main.cpp
	emilpro/mainwindow.cpp
	emilpro/editinstructiondialog.cpp
	)
	
qt5_wrap_ui(UI_HEADERS
	emilpro/mainwindow.ui
	emilpro/editinstructiondialog.ui
	)
	
set_property(SOURCE ../emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

add_definitions(${Qt5Widgets_DEFINITIONS})

include_directories(
	../include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${CMAKE_BINARY_DIR}/install-binutils/include/
	${Qt5Widgets_INCLUDE_DIRS}
	${LIBXMLPP_INCLUDE_DIRS}
	${LIBCURL_INCLUDE_DIRS}
	)

add_executable (emilpro
	${BASE_SRCS}
	${GUI_SRCS}
	${UI_HEADERS}
	)

add_executable (tools/squash-instruction-models
	${BASE_SRCS}
	../../tools/squash-instruction-models.cc
	)

set_property(TARGET emilpro APPEND PROPERTY OBJECT_DEPENDS binutils)
set_property(TARGET tools/squash-instruction-models APPEND PROPERTY OBJECT_DEPENDS binutils)

set (BASE_LIBS
	${LIBELF_LIBRARIES}
	opcodes.a
	bfd.a
	iberty.a
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)


target_link_libraries(emilpro
	${Qt5Widgets_LIBRARIES}
	${BASE_LIBS}
	)

target_link_libraries(tools/squash-instruction-models
	${BASE_LIBS}
	)
