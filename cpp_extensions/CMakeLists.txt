cmake_minimum_required(VERSION 3.15)
project(security_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release build with optimizations
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find Python and pybind11
find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

# Find pybind11 — try system install first, then fall back to pip-installed
find_package(pybind11 CONFIG QUIET)
if(NOT pybind11_FOUND)
  execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import pybind11; print(pybind11.get_cmake_dir())"
    OUTPUT_VARIABLE PYBIND11_CMAKE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(PYBIND11_CMAKE_DIR)
    list(APPEND CMAKE_PREFIX_PATH "${PYBIND11_CMAKE_DIR}")
    find_package(pybind11 REQUIRED CONFIG)
  else()
    message(FATAL_ERROR "pybind11 not found. Install with: pip install pybind11")
  endif()
endif()

# Source files
set(SOURCES
    src/mitre_graph.cpp
    src/pattern_matcher.cpp
    src/bindings.cpp
)

# Build the extension module
pybind11_add_module(security_cpp ${SOURCES})

target_include_directories(security_cpp PRIVATE include)

# Enable threading
find_package(Threads REQUIRED)
target_link_libraries(security_cpp PRIVATE Threads::Threads)

# Platform-specific flags
if(APPLE)
  target_compile_options(security_cpp PRIVATE -Wall -Wextra)
  # macOS: ensure C++17 atomics don't need libatomic
  set_target_properties(security_cpp PROPERTIES LINK_FLAGS "")
elseif(UNIX)
  target_compile_options(security_cpp PRIVATE -Wall -Wextra)
  target_link_libraries(security_cpp PRIVATE atomic)
elseif(WIN32)
  target_compile_options(security_cpp PRIVATE /W3 /O2)
endif()

# Install to the langchain_pipeline directory so Python can import it
install(
  TARGETS security_cpp
  DESTINATION "${CMAKE_SOURCE_DIR}/../langchain_pipeline"
)

message(STATUS "Building security_cpp extension")
message(STATUS "  Python: ${Python3_EXECUTABLE}")
message(STATUS "  pybind11: ${pybind11_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
