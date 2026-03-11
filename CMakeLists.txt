cmake_minimum_required(VERSION 3.11)

set(TARGET_NAME salesforce)

# Set C++17 as the required standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT EMSCRIPTEN)
    find_package(OpenSSL REQUIRED)
    if(NOT OpenSSL_FOUND)
        message(FATAL_ERROR "OpenSSL not found")
    endif()
endif()

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include duckdb/third_party/httplib duckdb/third_party/yyjson/include)

if (NOT EMSCRIPTEN)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

set(EXTENSION_SOURCES 
    src/salesforce_extension.cpp
    src/salesforce_object.cpp
    src/salesforce_metadata_cache.cpp
    src/salesforce_secret.cpp
)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Enable compiler warnings for extension source files
if(NOT MSVC)
    target_compile_options(${EXTENSION_NAME} PRIVATE -Wall -Wextra)
    target_compile_options(${LOADABLE_EXTENSION_NAME} PRIVATE -Wall -Wextra)
endif()

if (NOT EMSCRIPTEN)
    target_link_libraries(${EXTENSION_NAME} ${OPENSSL_LIBRARIES} ${WIN_LIBS})
    target_link_libraries(${LOADABLE_EXTENSION_NAME} ${OPENSSL_LIBRARIES} ${WIN_LIBS})
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

