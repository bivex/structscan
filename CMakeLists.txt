cmake_minimum_required(VERSION 3.15)
project(structscan CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/utf-8)
endif()
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
    src/FlowEngine.cpp
)

add_library(structscan SHARED ${SOURCES})

target_link_libraries(structscan PRIVATE dbgeng dbghelp)

# Standalone DLL configuration
if(NOT DEFINED STRUCTSCAN_OUTPUT_NAME)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64" OR CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "ARM64")
        set(STRUCTSCAN_OUTPUT_NAME "structscan_arm64")
    else()
        set(STRUCTSCAN_OUTPUT_NAME "structscan_x64")
    endif()
endif()

set_target_properties(structscan PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${STRUCTSCAN_OUTPUT_NAME}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

if(MINGW)
    target_link_options(structscan PRIVATE -static-libgcc -static-libstdc++ -Wl,--enable-auto-image-base)
endif()
