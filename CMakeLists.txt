cmake_minimum_required (VERSION 3.21)
project (emilpro LANGUAGES CXX C ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)

# Qt setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_compile_options(-fsanitize=address,undefined -g)
add_link_options(-fsanitize=address,undefined -g)

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(fmt REQUIRED)
find_package(trompeloeil REQUIRED)
find_package(doctest REQUIRED)
find_package(capstone REQUIRED)
find_package(etl REQUIRED)
find_package(bfd REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_subdirectory(src)
add_subdirectory(qt)
add_subdirectory(tools)

add_library(emilpro_interface INTERFACE)
target_include_directories(emilpro_interface INTERFACE include)
