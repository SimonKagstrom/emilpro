# From https://gitlab.com/lfortran/lfortran/-/blob/master/cmake/FindBFD.cmake
find_path(BFD_INCLUDE_DIR bfd.h)
find_library(BFD_LIBRARY bfd)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(bfd DEFAULT_MSG BFD_INCLUDE_DIR BFD_LIBRARY)

add_library(p::bfd INTERFACE IMPORTED)
set_property(TARGET p::bfd PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${BFD_INCLUDE_DIR})
set_property(TARGET p::bfd PROPERTY INTERFACE_LINK_LIBRARIES
    ${BFD_LIBRARY})
