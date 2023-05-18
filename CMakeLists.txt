cmake_minimum_required(VERSION 3.16)
project(hasher)

set(CMAKE_CXX_STANDARD 17)

AUX_SOURCE_DIRECTORY(. SRC_DIRS)

set(CMAKE_CXX_STANDARD 17)
include_directories("${PROJECT_SOURCE_DIR}")
include_directories("include")

add_executable(hasher main.cpp)

add_subdirectory("crypto")

target_link_libraries(hasher crypto)
