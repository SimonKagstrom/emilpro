cmake_minimum_required (VERSION 3.21)
project (emilpro LANGUAGES CXX C ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)

# Qt setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Enable sanitizers in debug builds
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -g)
    add_link_options(-fsanitize=address,undefined -g)
endif()

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(fmt REQUIRED)
find_package(capstone REQUIRED)
find_package(libiberty REQUIRED)
find_package(etl REQUIRED)
find_package(bfd REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_subdirectory(src)
add_subdirectory(qt)
add_subdirectory(tools)

# Unit tests are only built in debug mode
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    enable_testing()
    add_subdirectory(test)
endif()

add_library(emilpro_interface INTERFACE)
target_include_directories(emilpro_interface INTERFACE include)
