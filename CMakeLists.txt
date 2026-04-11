# How to use:
#   mkdir build
#   cd build
#   cmake ..
#   make
#
cmake_minimum_required(VERSION 3.15)

project(API LANGUAGES C)

add_executable(api_server
  main.c
  dotenv/dotenv.c
  middleware/auth.c
  logger/logger.c
  http/http_parser.c
  http/http_response.c
  router/router.c

)

target_compile_options(api_server
  PRIVATE -Wall -Wextra -pedantic -g -O2
)

set_target_properties(api_server
  PROPERTIES
    C_STANDARD 11
    C_EXTENSIONS OFF
)