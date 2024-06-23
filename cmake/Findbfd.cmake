# From https://gitlab.com/lfortran/lfortran/-/blob/master/cmake/FindBFD.cmake
find_path(BFD_INCLUDE_DIR bfd.h)

find_library(OPCODES_LIBRARY opcodes)
find_library(SFRAME_LIBRARY sframe)
find_library(ZSTD_LIBRARY zstd)
find_library(BFD_LIBRARY bfd)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(bfd DEFAULT_MSG BFD_INCLUDE_DIR BFD_LIBRARY)

add_library(p::bfd INTERFACE IMPORTED)

set_property(TARGET p::bfd PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${BFD_INCLUDE_DIR}
)

if (APPLE)
set_property(TARGET p::bfd PROPERTY INTERFACE_LINK_LIBRARIES
    ${BFD_LIBRARY}
    # On MacOS, these are not linked automatically
    ${OPCODES_LIBRARY}
    ${SFRAME_LIBRARY}
    ${ZSTD_LIBRARY}
    z
)
else()
set_property(TARGET p::bfd PROPERTY INTERFACE_LINK_LIBRARIES
    ${BFD_LIBRARY}
)
endif()
