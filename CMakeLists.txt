cmake_minimum_required(VERSION 3.14)
project(structscan VERSION 2.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_library(structscan SHARED src/Main.cpp include/structscan.h)

if (WIN32)
    target_link_libraries(structscan PRIVATE dbgeng user32)
endif()
