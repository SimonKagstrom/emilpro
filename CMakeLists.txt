cmake_minimum_required (VERSION 2.6)

# ====================================
# project name and version
# ====================================
project (emilpro)


set (CMAKE_MODULE_PATH  ${CMAKE_MODULE_PATH}
                        ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Dependencies
find_package (LibElf REQUIRED)
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
pkg_check_modules(LIBCURL libcurl)
pkg_check_modules(CGICC cgicc)

set (CMAKE_CXX_FLAGS "-std=c++0x -Wall -D_GLIBCXX_USE_NANOSLEEP -DPACKAGE=emilpro -DPACKAGE_VERSION=1")

if (HAVE_BFD_MULTIARCH)
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_BFD_MULTIARCH")
endif (HAVE_BFD_MULTIARCH)

set (CMAKE_BUILD_TYPE debug)

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

add_custom_target(emilpro_glade ALL
	DEPENDS emilpro_glade.hh
)


add_custom_command (OUTPUT built_in_instruction_models.hh
  COMMAND ${CMAKE_BINARY_DIR}/file-to-source ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh built_in_instruction_models_xml
  	${CMAKE_SOURCE_DIR}/data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/data/instruction-models/mips.xml
  DEPENDS
  	${CMAKE_SOURCE_DIR}/data/instruction-models/i386.xml 
  	${CMAKE_SOURCE_DIR}/data/instruction-models/mips.xml
  	file-to-source
)

add_custom_target(emilpro_built_in_instruction_models ALL
	DEPENDS built_in_instruction_models.hh
)

set (BASE_SRCS
	src/architecturefactory.cc
	src/bfd-disassembly.cc
	src/bfd-provider.cc
	src/configuration.cc
	src/emilpro.cc
	src/instructionfactory.cc
	src/jumptargetdisplay.cc
	src/model.cc
	src/network-listener.cc
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
	)
	
set_property(SOURCE src/gtk/main.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/emilpro_glade.hh)
set_property(SOURCE src/emilpro.cc APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_BINARY_DIR}/built_in_instruction_models.hh)

include_directories(
	src/gtk/include/
	src/include/
	${CMAKE_BINARY_DIR}
	${LIBELF_INCLUDE_DIRS}
	${LIBBFD_INCLUDE_DIRS}
	${GTKMM_INCLUDE_DIRS}
	${GTKSOURCEVIEWMM_INCLUDE_DIRS}
	${LIBXMLPP_INCLUDE_DIRS}
	${LIBCURL_INCLUDE_DIRS}
	)

add_executable (emilpro
	${BASE_SRCS}
	${GUI_SRCS}
	)

add_executable (tools/squash-instruction-models
	${BASE_SRCS}
	tools/squash-instruction-models.cc
	)

add_executable (tools/test-remote-communication
	${BASE_SRCS}
	tools/test-remote-communication.cc
	)

add_executable (server/cgi-server
	${BASE_SRCS}
	src/server/cgi-server.cc
	tools/cgi-server-main.cc
	)

add_executable (server/cgi-handler
	src/utils.cc
	tools/cgi-handler.cc
	)
	
target_link_libraries(emilpro
	${LIBELF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${GTKMM_LIBRARIES}
	${GTKSOURCEVIEWMM_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)

target_link_libraries(tools/squash-instruction-models
	${LIBELF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)

target_link_libraries(tools/test-remote-communication
	${LIBELF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)

target_link_libraries(server/cgi-server
	${LIBELF_LIBRARIES}
	${LIBBFD_LIBRARIES}
	${LIBXMLPP_LIBRARIES}
	${LIBCURL_LIBRARIES}
	z
	)

target_link_libraries(server/cgi-handler
	${CGICC_LIBRARIES}
	z
	)
