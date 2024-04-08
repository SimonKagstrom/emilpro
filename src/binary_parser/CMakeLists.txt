add_library(elf_binary_parser EXCLUDE_FROM_ALL
    elf_binary_parser.cc
)

target_link_libraries(elf_binary_parser
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
    elf_binary_parser
)
