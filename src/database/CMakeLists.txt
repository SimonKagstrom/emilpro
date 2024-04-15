add_library(database EXCLUDE_FROM_ALL
    database.cc
)

target_link_libraries(database
PUBLIC
    emilpro_interface
PRIVATE
    fmt::fmt
    capstone_disassembler
    binary_parser_factory
)
