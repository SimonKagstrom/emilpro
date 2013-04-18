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
find_package (LibBfd REQUIRED)
find_package (LibCRPCUT REQUIRED)
find_package (PkgConfig REQUIRED)

pkg_check_modules(GTKMM gtkmm-3.0)
pkg_check_modules(LIBXMLPP libxml++-2.6)

set (TGT ut)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE debug)

set (${TGT}_SRCS
	../../src/architecturefactory.cc
	../../src/bfd-disassembly.cc
	../../src/bfd-provider.cc
	../../src/configuration.cc
	../../src/emilpro.cc
	../../src/gtk/hexview.cc
	../../src/jumptargetdisplay.cc
	../../src/symbolfactory.cc
	../../src/utils.cc
	../../src/xmlfactory.cc
	main.cc
	tests/tests-disassembly.cc
	tests/tests-hexview.cc
	tests/tests-instructionfactory.cc
	tests/tests-jumptargetdisplay.cc
	tests/tests-model.cc
	tests/tests-symbol-provider.cc
	tests/tests-utils.cc
	tests/tests-xmlfactory.cc
	)

include_directories(
	../../src/gtk/include/
	../../src/include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${LIBBFD_INCLUDE_DIRS}
	${LIBCRPCUT_INCLUDE_DIRS}
	${GTKMM_INCLUDE_DIRS}
	${LIBXMLPP_INCLUDE_DIRS}
	)

add_executable (test-binary
	elf-assembly.S
	elf-example-source.cc)

add_executable (file-to-source
	../../src/utils.cc
	../../tools/file-to-source.cc
)

add_custom_command (OUTPUT built_in_instruction_models.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh built_in_instruction_models_xml
  	${CMAKE_SOURCE_DIR}/../../data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/../../data/instruction-models/mips.xml
  DEPENDS
  	${CMAKE_SOURCE_DIR}/../../data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/../../data/instruction-models/mips.xml
  	file-to-source
)

add_custom_target(emilpro_built_in_instruction_models ALL
	DEPENDS built_in_instruction_models.hh
)
set_property(SOURCE ../../src/emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

add_executable (${TGT} ${${TGT}_SRCS})
target_link_libraries(${TGT}
	${LIBELF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBCRPCUT_LIBRARIES}
	${GTKMM_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
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
