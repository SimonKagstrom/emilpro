add_library(bfd_binary_parser EXCLUDE_FROM_ALL
    bfd_binary_parser.cc
)

target_link_libraries(bfd_binary_parser
PUBLIC
    emilpro_interface
    p::bfd
    fmt::fmt
PRIVATE
    section
)


add_library(binary_parser_factory EXCLUDE_FROM_ALL
    binary_parser_factory.cc
)

target_link_libraries(binary_parser_factory
PRIVATE
    bfd_binary_parser
)
