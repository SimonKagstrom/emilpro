cmake_minimum_required (VERSION 3.21)
project (emilpro LANGUAGES CXX C ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)

# Qt setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(fmt REQUIRED)
find_package(trompeloeil REQUIRED)
find_package(doctest REQUIRED)
find_package(capstone REQUIRED)
find_package(libelfin REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_subdirectory(qt)
