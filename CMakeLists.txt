project(WenkitSQLite CXX)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_COLOR_MAKEFILE ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_BUILD_TYPE Debug)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
endif (CMAKE_BUILD_TYPE MATCHES "Debug")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" "${PROJECT_SOURCE_DIR}/../../cmake" ${CMAKE_MODULE_PATH})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

find_package(Sqlite3 REQUIRED)
find_package(GTest REQUIRED)
find_package(Glog REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/test)

include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${GLOG_INCLUDE_DIRS})

set(INCLUDE_SRC
    ./DatabaseAuthorizer.h
    ./SQLValue.h
    ./SQLiteDatabase.h
    ./SQLiteFileSystem.h
    ./SQLiteStatement.h
    ./SQLiteTransaction.h)

set(LIB_SRC
    ./DatabaseAuthorizer.cpp
    ./SQLValue.cpp
    ./SQLiteAuthorizer.cpp
    ./SQLiteDatabase.cpp
    ./SQLiteFileSystem.cpp
    ./SQLiteStatement.cpp
    ./SQLiteTransaction.cpp)

set(TARGET unitTest)

add_executable(${TARGET}
    ${LIB_SRC}
    ./test/test_SQLite.cpp)

target_link_libraries(${TARGET}
			${SQLITE3_LIBRARY_RELEASE}
			${GTEST_BOTH_LIBRARIES}
			${GLOG_LIBRARIES}
			pthread)

set(GTEST_ARGS "--gtest_color=yes ")
enable_testing()
add_test(SQLiteWrapperCPPWebkit ${CMAKE_CURRENT_BINARY_DIR}/${TARGET} ${GTEST_ARGS})

