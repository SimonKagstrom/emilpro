
add_library(mainwindow EXCLUDE_FROM_ALL
    highlighter.cc
    instruction_delegate.cc
    jump_lane_delegate.cc
    mainwindow.ui
    mainwindow.cc
)

target_link_libraries(mainwindow
PUBLIC
    Qt6::Widgets
    fmt::fmt
    database
    address_history
    jump_lanes
)

add_executable(emilpro
    main.cc
)

target_link_libraries(emilpro
    mainwindow
    binary_parser_factory
    capstone_disassembler
)
