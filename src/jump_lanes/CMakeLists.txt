add_library(jump_lanes EXCLUDE_FROM_ALL
    jump_lanes.cc
)

target_link_libraries(jump_lanes
PUBLIC
    emilpro_interface
PRIVATE
    fmt::fmt
    etl::etl
)

target_include_directories(jump_lanes
PUBLIC
    include
)
