add_library(address_history EXCLUDE_FROM_ALL
    address_history.cc
)

target_link_libraries(address_history
PUBLIC
    emilpro_interface
)
