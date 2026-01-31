cmake_minimum_required(VERSION 3.24)
project(libtouchstone CXX)

option(LIBTOUCHSTONE_FETCH_DEPS "Let libtouchstone fetch its own deps" ON)

if(LIBTOUCHSTONE_FETCH_DEPS)
  include(FetchContent)

  # Only fetch if the targets are not already provided by the parent project.
  if(NOT TARGET cpr::cpr)
    FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr GIT_TAG 1.10.5)
    FetchContent_MakeAvailable(cpr)
  endif()

  if(NOT TARGET lexbor OR NOT TARGET lexbor_static)
    if(BUILD_SHARED_LIBS)
      set(LEXBOR_BUILD_SHARED ON CACHE BOOL "")
      set(LEXBOR_BUILD_STATIC OFF CACHE BOOL "")
    else()
      set(LEXBOR_BUILD_SHARED OFF CACHE BOOL "")
      set(LEXBOR_BUILD_STATIC ON CACHE BOOL "")
    endif()
    FetchContent_Declare(lexbor GIT_REPOSITORY https://github.com/lexbor/lexbor.git GIT_TAG v2.3.0)
    FetchContent_MakeAvailable(lexbor)
  endif()

  if(NOT TARGET json)
    FetchContent_Declare(json_cpp GIT_REPOSITORY https://github.com/jart/json.cpp GIT_TAG main)
    FetchContent_MakeAvailable(json_cpp)
    target_include_directories(json PUBLIC ${json_cpp_SOURCE_DIR})
  endif()
endif()

if(NOT TARGET lexbor_lib)
  if(TARGET lexbor_static)
    # default to static since it seems to only exist if shared is disabled
    add_library(lexbor_lib ALIAS lexbor_static)
  elseif(TARGET lexbor)
    # Fallback to shared if that's all we have
    add_library(lexbor_lib ALIAS lexbor)
  else()
    message(FATAL_ERROR "lexbor_lib alias failed: No lexbor targets found.")
  endif()
endif()

add_library(libtouchstone libtouchstone.cc sso.cc) # Build the library.

# Public surface only exposes cpr; others are internal implementation details.
target_link_libraries(libtouchstone PUBLIC cpr::cpr PRIVATE lexbor_lib json)
target_compile_features(libtouchstone PUBLIC cxx_std_17) # Use C++17.
target_include_directories(libtouchstone PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

# Provide a namespaced alias for consumers.
add_library(libtouchstone::libtouchstone ALIAS libtouchstone)

# Only build the example when this is the top-level project.
if(PROJECT_IS_TOP_LEVEL)
  add_executable(example example.cc)
  target_link_libraries(example libtouchstone json)
endif()
