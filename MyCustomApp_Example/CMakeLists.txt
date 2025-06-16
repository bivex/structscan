cmake_minimum_required(VERSION 3.10)

project(MyCustomApp_Example CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(MyCustomApp main.cpp)

# Add flags to generate PDB for Release build on MSVC
set_target_properties(MyCustomApp PROPERTIES
    CMAKE_CXX_FLAGS_RELEASE "/Zi"
    CMAKE_EXE_LINKER_FLAGS_RELEASE "/DEBUG /INCREMENTAL:NO"
) 