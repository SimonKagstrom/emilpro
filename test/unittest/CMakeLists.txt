add_executable(ut
    test_database.cc
    main.cc
)

target_link_libraries(ut
    trompeloeil::trompeloeil
    doctest::doctest
    database
)
