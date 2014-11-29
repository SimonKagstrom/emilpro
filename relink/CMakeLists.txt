cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro-ut)
set (PROJECT_VERSION "1.0.0")

enable_language(ASM)

# Dependencies
set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)
set (BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)


find_package (LibElf REQUIRED)
find_package (PkgConfig REQUIRED)
include (${CMAKE_CURRENT_SOURCE_DIR}/../cmake/BuildBinutils.cmake)

pkg_check_modules(LIBXMLPP libxml++-2.6)
pkg_check_modules(LIBCURL libcurl)

set (TGT relink)

set (CMAKE_CXX_FLAGS "-std=c++0x -g -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/install-binutils/lib ${CMAKE_BINARY_DIR}/install-binutils/lib64 /home/ska/local/lib)

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE Relase)

set (${TGT}_SRCS
	../src/architecturefactory.cc
	../src/instructionfactory.cc
	../src/bfd-disassembly.cc
	../src/bfd-provider.cc
	../src/configuration.cc
	../src/emilpro.cc
	../src/model.cc
	../src/namemangler.cc
	../src/network-listener.cc
	../src/server-connection.cc
	../src/preferences.cc
	../src/symbolfactory.cc
	../src/utils.cc
	../src/xmlfactory.cc
	../src/xmlstring.cc
	main.cc
	)

include_directories(
	../src/include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${CMAKE_BINARY_DIR}/install-binutils/include/
	${LIBXMLPP_INCLUDE_DIRS}
	${LIBCURL_INCLUDE_DIRS}
	)

add_executable (file-to-source
	../src/utils.cc
	../tools/file-to-source.cc
)

add_custom_command (OUTPUT built_in_instruction_models.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh built_in_instruction_models_xml
  	${CMAKE_SOURCE_DIR}/../data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/../data/instruction-models/mips.xml
  DEPENDS
  	${CMAKE_SOURCE_DIR}/../data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/../data/instruction-models/mips.xml
  	file-to-source
)

add_custom_target(emilpro_built_in_instruction_models ALL
	DEPENDS built_in_instruction_models.hh
)
set_property(SOURCE ../src/emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	opcodes.a
	bfd.a
	iberty.a
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	pthread
	dl
	)

set_property(TARGET ${TGT} APPEND PROPERTY OBJECT_DEPENDS binutils)

add_library(first SHARED example/first.cc)
add_library(second SHARED example/second.cc)
add_executable(example example/example.cc)

target_link_libraries(first second)
target_link_libraries(example first)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS)
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS) 
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS) 
