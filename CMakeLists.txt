cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro)
set (PROJECT_VERSION_MAJOR  1)
set (PROJECT_VERSION_MINOR  0)
set (PROJECT_VERSION_PATCH  0)
set (PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP")

set (TGT emilpro)

set (CMAKE_BUILD_TYPE debug)

set (${TGT}_SRCS
	src/disassembly.cc
	src/elf.cc
	src/utils.cc
	target/main.cc
	)

include_directories(
	src/include/
	/home/ska/local/include
	)

link_directories (
	/home/ska/local/lib
)


add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	elf
	opdis
	bfd
	opcodes
	iberty
	z
	)
