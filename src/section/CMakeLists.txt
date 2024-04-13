add_library(section EXCLUDE_FROM_ALL
    section.cc
)

target_link_libraries(section
PUBLIC
    emilpro_interface
)

target_include_directories(section
PUBLIC
    include
)
