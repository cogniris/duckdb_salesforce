cmake_minimum_required(VERSION 3.11)  # Increased minimum version for FetchContent

# Set extension name here
set(TARGET_NAME salesforce)

# Set policy to use <PackageName>_ROOT variables
cmake_policy(SET CMP0074 NEW)

# Call project() early to set up system-specific search paths
project(${TARGET_NAME})

# Set paths for dependencies
set(CURL_ROOT "/opt/homebrew/opt/curl")
set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Include nlohmann_json as a header-only library
include(FetchContent)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

include_directories(src/include)
include_directories(${json_SOURCE_DIR}/include)  # Include nlohmann_json headers directly

set(EXTENSION_SOURCES 
    src/salesforce_extension.cpp
    src/salesforce_object.cpp
)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link OpenSSL and CURL in both the static library and the loadable extension
# But don't link nlohmann_json as a target, since we're including it directly
target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

