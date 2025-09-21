# How to use:
#   mkdir build
#   cd build
#   cmake ..
#   make
#
cmake_minimum_required(VERSION 4.1)

project(API
  LANGUAGES CXX C
)

add_executable(api_server
  main.c
  dotenv/dotenv.c
  middleware/auth.c
)

target_compile_options(api_server
  PRIVATE
    "-Wall" "-Wextra" "-pedantic" "-g" "-O2" "-luuid"
)

set_target_properties(api_server
  PROPERTIES
    CXX_STANDARD 17
    CXX_EXTENSIONS OFF
)