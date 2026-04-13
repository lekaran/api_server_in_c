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
  DB/db.c
  handler/register.c
)

set(ENV{PKG_CONFIG_PATH} "/opt/homebrew/opt/mysql-client/lib/pkgconfig:/opt/homebrew/Cellar/cjson/1.7.19/lib/pkgconfig")

find_package(PkgConfig REQUIRED)

pkg_check_modules(MYSQLCLIENT REQUIRED mysqlclient)
pkg_check_modules(CJSON REQUIRED libcjson)

target_include_directories(api_server PRIVATE ${MYSQLCLIENT_INCLUDE_DIRS})
target_link_directories(api_server PRIVATE ${MYSQLCLIENT_LIBRARY_DIRS})
target_link_libraries(api_server PRIVATE ${MYSQLCLIENT_LIBRARIES})

target_include_directories(api_server PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_directories(api_server PRIVATE ${CJSON_LIBRARY_DIRS})
target_link_libraries(api_server PRIVATE ${CJSON_LIBRARIES})

target_compile_options(api_server
  PRIVATE -Wall -Wextra -pedantic -g -O2
)

set_target_properties(api_server
  PROPERTIES
    C_STANDARD 11
    C_EXTENSIONS OFF
)