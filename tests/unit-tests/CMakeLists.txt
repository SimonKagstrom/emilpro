cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro-ut)
set (PROJECT_VERSION "1.0.0")

# Dependencies
set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

find_package (LibElf REQUIRED)
find_package (LibDwarf REQUIRED)
find_package (LibBfd REQUIRED)
find_package (LibOpdis REQUIRED)
find_package (LibCRPCUT REQUIRED)

set (TGT ut)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP")
set (CMAKE_BUILD_TYPE debug)

set (${TGT}_SRCS
	../../src/disassembly.cc
	../../src/elf.cc
	../../src/symbolfactory.cc
	../../src/utils.cc
	main.cc
	tests/tests-disassembly.cc
	tests/tests-symbol-provider.cc
	)

include_directories(
	../../src/include/
	${LIBELF_INCLUDE_DIRS}
	${LIBDWARF_INCLUDE_DIRS}
	${LIBOPDIS_INCLUDE_DIRS}
	${LIBBFD_INCLUDE_DIRS}
	${LIBCRPCUT_INCLUDE_DIRS}
	)

add_executable (test-binary test-elf.cc)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	${LIBDWARF_LIBRARIES}
	${LIBOPDIS_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBCRPCUT_LIBRARIES}
	gtest
	z
	pthread
	dl
	)
