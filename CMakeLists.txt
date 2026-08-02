cmake_minimum_required(VERSION 3.14)
project(structscan VERSION 1.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(structscan SHARED Main.cpp Main.h)

if (WIN32)
    target_link_libraries(structscan PRIVATE dbgeng user32)
endif()
