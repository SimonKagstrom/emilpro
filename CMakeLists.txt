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
find_package (LibOpdis REQUIRED)

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
	src/symbolfactory.cc
	src/utils.cc
	target/main.cc
	)

include_directories(
	src/include/
	${LIBELF_INCLUDE_DIRS}
	${LIBDWARF_INCLUDE_DIRS}
	${LIBOPDIS_INCLUDE_DIRS}
	${LIBBFD_INCLUDE_DIRS}
	)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	${LIBDWARF_LIBRARIES}
	${LIBOPDIS_LIBRARIES}
	${LIBBFD_LIBRARIES}
	z
	)
