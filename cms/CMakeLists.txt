include(FetchContent)
cmake_minimum_required(VERSION 3.20)
project(CMS LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL    REQUIRED)
find_package(Threads REQUIRED)

# SQLite3 — find manually since target name varies by distro
find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
find_library(SQLITE3_LIB NAMES sqlite3)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/CMS_server.cpp
    src/CMS_Info_routes.cpp
    src/CMS_update_routes.cpp
    src/CUT_upload_routes.cpp
    src/CMS_ATM.cpp
    src/ATMs_db.cpp
)

FetchContent_Declare(
    crow
    URL https://github.com/CrowCpp/Crow/releases/download/v1.3.2/Crow-1.3.2-Linux.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP true
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/crow
    BINARY_DIR ${CMAKE_BINARY_DIR}/extern/crow
)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/archive/refs/tags/v3.12.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP true
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/nlohmann_json
    BINARY_DIR ${CMAKE_BINARY_DIR}/extern/nlohmann_json
)

FetchContent_MakeAvailable(crow)
FetchContent_MakeAvailable(nlohmann_json)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/crow/include
    ${SQLITE3_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    CURL::libcurl
    Threads::Threads
    nlohmann_json
    ${SQLITE3_LIB}
)
