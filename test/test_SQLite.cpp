#include "DatabaseAuthorizer.h"
#include "SQLValue.h"
#include "SQLiteDatabase.h"
#include "SQLiteTransaction.h"
#include "SQLiteStatement.h"
#include "SQLiteFileSystem.h"

#include <iostream>
#include <fstream>
#include <thread>
#include <algorithm>
#include <vector>
#include <cstdio>

#include <sqlite3.h>
#include "gtest/gtest.h"

TEST(SQLiteWrapperCPPWebkit, test_create_sqlitedb_file)
{
    const std::string filenameDB("testDB.db");
    std::shared_ptr<SQLiteDatabase> sqliteDB(new SQLiteDatabase());

    // Open the db, if it doen't exist
    // create it.
    sqliteDB->open(filenameDB, false);
    ASSERT_TRUE(sqliteDB->isOpen());

    // Check if the file was created.
    std::ifstream ifile(filenameDB.c_str());
    ASSERT_TRUE(ifile.good());

    // Close db file.
    sqliteDB->close();
    ASSERT_FALSE(sqliteDB->isOpen());

    // Remove file.
    std::remove(filenameDB.c_str());
}

TEST(SQLiteWrapperCPPWebkit, test_populate_sqlitedb)
{
    const std::string filenameDB("testDB.db");
    std::shared_ptr<SQLiteDatabase> sqliteDB(new SQLiteDatabase());

    // Open the db, if it doen't exist
    // create it.
    sqliteDB->open(filenameDB, false);
    ASSERT_TRUE(sqliteDB->isOpen());

    // Check if the file was created.
    std::ifstream ifile(filenameDB.c_str());
    ASSERT_TRUE(ifile.good());

    // Create a table
    ASSERT_TRUE(SQLiteStatement(*sqliteDB, std::string("CREATE TABLE user (userID INTEGER NOT NULL PRIMARY KEY, lastName VARCHAR(50) NOT NULL, firstName VARCHAR(50), age INTEGER, weight DOUBLE)")).executeCommand());

    // Populate the table created above
    ASSERT_TRUE(SQLiteStatement(*sqliteDB, std::string("INSERT INTO user (userID, lastName, firstName, age, weight) VALUES (1, 'Lehmann', 'Jamie', 20, 65.5)")).executeCommand());
    ASSERT_TRUE(SQLiteStatement(*sqliteDB, std::string("INSERT INTO user (userID, lastName, firstName, age, weight) VALUES (2, 'Burgdorf', 'Peter', 55, NULL)")).executeCommand());
    ASSERT_TRUE(SQLiteStatement(*sqliteDB, std::string("INSERT INTO user (userID, lastName, firstName, age, weight) VALUES (3, 'Lehmann', 'Fernando', 18, 70.2)")).executeCommand());
    ASSERT_TRUE(SQLiteStatement(*sqliteDB, std::string("INSERT INTO user (userID, lastName, firstName, age, weight) VALUES (4, 'Lehmann', 'Carlene ', 17, 50.8)")).executeCommand());

    // Close db file.
    sqliteDB->close();
    ASSERT_FALSE(sqliteDB->isOpen());

    // Remove file.
    std::remove(filenameDB.c_str());
}


int main(int argc, char *argv[])
{
    ::testing::GTEST_FLAG(color) = "yes";
    ::testing::GTEST_FLAG(print_time) = false;

    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
