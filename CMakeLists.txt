project(WenkitSQLite CXX)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" "${PROJECT_SOURCE_DIR}/../../cmake" ${CMAKE_MODULE_PATH})

add_definitions(-DDEBUG -std=c++0x)

find_package(Sqlite3 REQUIRED)
find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/test)

include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${GTEST_INCLUDE_DIRS})

set(TARGET unitTest)

add_executable(${TARGET}
    ./DatabaseAuthorizer.cpp
    ./SQLValue.cpp
    ./SQLiteAuthorizer.cpp
    ./SQLiteDatabase.cpp
    ./SQLiteFileSystem.cpp
    ./SQLiteStatement.cpp
    ./SQLiteTransaction.cpp
    ./test/test_SQLite.cpp)

target_link_libraries(${TARGET} ${SQLITE3_LIBRARIES} ${GTEST_BOTH_LIBRARIES} pthread)

set(GTEST_ARGS "--gtest_color=yes ")
enable_testing()
add_test(test ${CMAKE_CURRENT_BINARY_DIR}/${TARGET} ${GTEST_ARGS})

