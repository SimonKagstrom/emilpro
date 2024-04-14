
add_library(mainwindow EXCLUDE_FROM_ALL
    mainwindow.ui
    mainwindow.cc
)

target_link_libraries(mainwindow
PUBLIC
    Qt6::Widgets
    fmt::fmt
    database
)

add_executable(emilpro
    main.cc
)

target_link_libraries(emilpro
    mainwindow
    binary_parser_factory
    capstone_disassembler
)
