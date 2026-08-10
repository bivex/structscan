cmake_minimum_required(VERSION 3.15)
project(structscan CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/Main.cpp
    src/Utils.cpp
    src/SmartFieldAnalyzer.cpp
    src/ScanEngine.cpp
    src/ListCrossRefEngine.cpp
    src/HeaderSynthesizer.cpp
    src/EntropyEngine.cpp
    src/UafEngine.cpp
)

add_library(structscan SHARED ${SOURCES})

target_link_libraries(structscan PRIVATE dbgeng dbghelp)
