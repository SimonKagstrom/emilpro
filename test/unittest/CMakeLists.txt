add_executable(ut
    test_address_history.cc
    test_database.cc
    test_lanes.cc
    main.cc
)

target_link_libraries(ut
    trompeloeil::trompeloeil
    doctest::doctest
    address_history
    database
    jump_lanes
    fmt::fmt
)
