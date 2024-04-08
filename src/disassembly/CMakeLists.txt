add_library(capstone_disassembler EXCLUDE_FROM_ALL
    capstone_disassembler.cc
)

target_link_libraries(capstone_disassembler
PUBLIC
    emilpro_interface
    capstone::capstone
    fmt::fmt
)

