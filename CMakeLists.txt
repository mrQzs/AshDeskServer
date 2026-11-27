cmake_minimum_required(VERSION 3.24)
project(AshDeskServer VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
  set(ASH_WARN /utf-8 /W4 /WX /fp:precise /GS /D_CRT_SECURE_NO_WARNINGS)
else()
  set(ASH_WARN -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
endif()

set(ASH_SANITIZE "" CACHE STRING "Sanitizer mode: address | address,undefined | thread")
if(ASH_SANITIZE)
  if(MSVC)
    if(NOT ASH_SANITIZE STREQUAL "address")
      message(FATAL_ERROR "MSVC only supports AddressSanitizer: -DASH_SANITIZE=address")
    endif()
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/fsanitize=address>)
    add_compile_definitions(
      $<$<COMPILE_LANGUAGE:CXX>:_DISABLE_VECTOR_ANNOTATION>
      $<$<COMPILE_LANGUAGE:CXX>:_DISABLE_STRING_ANNOTATION>
    )
    add_link_options(/INCREMENTAL:NO)
  else()
    add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fsanitize=${ASH_SANITIZE};-fno-omit-frame-pointer;-fno-sanitize-recover=all;-g>")
    add_link_options(-fsanitize=${ASH_SANITIZE})
  endif()
endif()

add_library(ash_core STATIC
  src/ash_platform.c
  src/ash_crypto.c
  src/ash_wire.c
  src/ash_ratelimit.c
  src/ash_registry.c
  src/ash_relay.c
  src/ash_server.c
)
target_include_directories(ash_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(ash_core PRIVATE "$<$<COMPILE_LANGUAGE:C>:${ASH_WARN}>")

if(WIN32)
  target_compile_definitions(ash_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  target_link_libraries(ash_core PUBLIC ws2_32 bcrypt)
else()
  find_package(Threads REQUIRED)
  target_compile_definitions(ash_core PUBLIC _GNU_SOURCE _POSIX_C_SOURCE=200809L)
  target_link_libraries(ash_core PUBLIC Threads::Threads)
endif()

add_executable(ash_server src/main_server.c)
target_link_libraries(ash_server PRIVATE ash_core)
target_compile_options(ash_server PRIVATE "$<$<COMPILE_LANGUAGE:C>:${ASH_WARN}>")

add_executable(ash_ctl src/main_ctl.c)
target_link_libraries(ash_ctl PRIVATE ash_core)
target_compile_options(ash_ctl PRIVATE "$<$<COMPILE_LANGUAGE:C>:${ASH_WARN}>")

add_executable(ash_bench tools/bench_relay.c)
target_link_libraries(ash_bench PRIVATE ash_core)
target_compile_options(ash_bench PRIVATE "$<$<COMPILE_LANGUAGE:C>:${ASH_WARN}>")

enable_testing()

set(ASH_HAVE_GTEST OFF)
if(WIN32)
  set(ASH_GTEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/googletest")
  if(NOT EXISTS "${ASH_GTEST_DIR}/lib/gtest.lib" AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../AshDesk/third_party/googletest/lib/gtest.lib")
    set(ASH_GTEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../AshDesk/third_party/googletest")
  endif()
  if(EXISTS "${ASH_GTEST_DIR}/lib/gtest.lib" AND EXISTS "${ASH_GTEST_DIR}/lib/gtest_main.lib")
    add_library(GTest::gtest STATIC IMPORTED)
    set_target_properties(GTest::gtest PROPERTIES
      IMPORTED_LOCATION "${ASH_GTEST_DIR}/lib/gtest.lib"
      INTERFACE_INCLUDE_DIRECTORIES "${ASH_GTEST_DIR}/include"
    )
    add_library(GTest::gtest_main STATIC IMPORTED)
    set_target_properties(GTest::gtest_main PROPERTIES
      IMPORTED_LOCATION "${ASH_GTEST_DIR}/lib/gtest_main.lib"
      INTERFACE_LINK_LIBRARIES GTest::gtest
    )
    set(ASH_HAVE_GTEST ON)
  endif()
else()
  enable_language(CXX)
  find_package(GTest QUIET)
  set(ASH_HAVE_GTEST ${GTest_FOUND})
endif()

if(ASH_HAVE_GTEST)
  enable_language(CXX)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  include(GoogleTest)

  add_executable(ash_gtest
    tests/gtest_crypto_wire.cpp
    tests/gtest_registry_relay.cpp
    tests/gtest_e2e_server.cpp
  )
  target_link_libraries(ash_gtest PRIVATE GTest::gtest_main ash_core)
  target_compile_options(ash_gtest PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:${ASH_WARN}>")
  gtest_discover_tests(ash_gtest DISCOVERY_MODE PRE_TEST)
else()
  message(WARNING "GoogleTest not found: ash_gtest will not be built")
endif()
