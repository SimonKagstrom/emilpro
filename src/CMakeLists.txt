add_subdirectory(binary_parser)
add_subdirectory(disassembly)

add_library(section EXCLUDE_FROM_ALL
    section.cc
)

target_link_libraries(section
PUBLIC
    emilpro_interface
)
