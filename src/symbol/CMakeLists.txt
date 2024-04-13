add_library(symbol EXCLUDE_FROM_ALL
    symbol.cc
)

target_link_libraries(symbol
PUBLIC
    emilpro_interface
PRIVATE
    p::bfd
    fmt::fmt
)

target_include_directories(symbol
PUBLIC
    include
)
