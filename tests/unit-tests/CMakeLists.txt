cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro-ut)
set (PROJECT_VERSION "1.0.0")

enable_language(ASM)

# Dependencies
set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

find_package (LibElf REQUIRED)
find_package (LibDwarf REQUIRED)
find_package (LibBfd REQUIRED)
find_package (LibOpdis REQUIRED)
find_package (LibCRPCUT REQUIRED)

set (TGT ut)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE debug)

set (${TGT}_SRCS
	../../src/architecturefactory.cc
	../../src/bfd-provider.cc
	../../src/disassembly.cc
	../../src/jumptargetdisplay.cc
	../../src/symbolfactory.cc
	../../src/utils.cc
	main.cc
	tests/tests-disassembly.cc
	tests/tests-jumptargetdisplay.cc
	tests/tests-model.cc
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

add_executable (test-binary
	elf-assembly.S
	elf-example-source.cc)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	${LIBDWARF_LIBRARIES}
	${LIBOPDIS_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBCRPCUT_LIBRARIES}
	gtest
	gmock
	z
	pthread
	dl
	)

add_custom_target (test-binary-asm-only ALL
  COMMAND ${CMAKE_C_COMPILER} -nostdlib ${CMAKE_CURRENT_SOURCE_DIR}/elf-assembly-start.S -o ${CMAKE_BINARY_DIR}/test-binary-asm-only
)

add_custom_target (test-binary.exe ALL
  COMMAND i586-mingw32msvc-g++ ${CMAKE_CURRENT_SOURCE_DIR}/elf-example-source.cc -o ${CMAKE_BINARY_DIR}/test-binary.exe
)

add_custom_target (test-binary-asm-only-32 ALL
  COMMAND ${CMAKE_C_COMPILER} -m32 -nostdlib ${CMAKE_CURRENT_SOURCE_DIR}/elf-assembly-start.S -o ${CMAKE_BINARY_DIR}/test-binary-asm-only-32
)

#add_custom_target (test-binary.mach-o ALL
#  DEPENDS test-binary
#  COMMAND objcopy -O mach-o-i386 ${CMAKE_BINARY_DIR}/test-binary ${CMAKE_BINARY_DIR}/test-binary.mach-o
#)
