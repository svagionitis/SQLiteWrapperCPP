/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define __STDC_FORMAT_MACROS
#include "SQLiteFileSystem.h"

#include "SQLiteDatabase.h"
#include "SQLiteStatement.h"
#include <inttypes.h>
#include <sqlite3.h>

#include <sstream>

#define D_LOG_DEBUG

#ifndef DEBUG
#define ASSERT(x)
#else
#define ASSERT(x) \
         if (! (x)) \
         { \
            cout << "ERROR!! Assert " << #x << " failed\n"; \
            cout << " on line " << __LINE__  << "\n"; \
            cout << " in file " << __FILE__ << "\n";  \
         }
#endif

SQLiteFileSystem::SQLiteFileSystem()
{
}

int SQLiteFileSystem::openDatabase(const std::string& filename, sqlite3** database, bool)
{
    return sqlite3_open(filename.data(), database);
}

std::string SQLiteFileSystem::getFileNameForNewDatabase(const std::string& dbDir, const std::string&,
                                                        const std::string&, SQLiteDatabase* db)
{
    // try to get the next sequence number from the given database
    // if we can't get a number, return an empty string
    SQLiteStatement sequenceStatement(*db, "SELECT seq FROM sqlite_sequence WHERE name='Databases';");
    if (sequenceStatement.prepare() != SQLResultOk)
        return std::string();
    int result = sequenceStatement.step();
    int64_t seq = 0;
    if (result == SQLResultRow)
        seq = sequenceStatement.getColumnInt64(0);
    else if (result != SQLResultDone)
        return std::string();
    sequenceStatement.finalize();

    // increment the number until we can use it to form a file name that doesn't exist
    std::string fileName;
    std::ostringstream stringStream;
    do {
        ++seq;

        stringStream << seq << ".db";
        //fileName = pathByAppendingComponent(dbDir, String::format("%016" PRIx64 ".db", seq));
        fileName = pathByAppendingComponent(dbDir, stringStream.str());
    } while (fileExists(fileName));

    return stringStream.str();
}

std::string SQLiteFileSystem::appendDatabaseFileNameToPath(const std::string& path, const std::string& fileName)
{
    return pathByAppendingComponent(path, fileName);
}

bool SQLiteFileSystem::ensureDatabaseDirectoryExists(const std::string& path)
{
    if (path.empty())
        return false;
    return makeAllDirectories(path);
}

bool SQLiteFileSystem::ensureDatabaseFileExists(const std::string& fileName, bool checkPathOnly)
{
    if (fileName.empty())
        return false;

    if (checkPathOnly) {
        String dir = directoryName(fileName);
        return ensureDatabaseDirectoryExists(dir);
    }

    return fileExists(fileName);
}

bool SQLiteFileSystem::deleteEmptyDatabaseDirectory(const std::string& path)
{
    return deleteEmptyDirectory(path);
}

bool SQLiteFileSystem::deleteDatabaseFile(const std::string& fileName)
{
    return deleteFile(fileName);
}

long long SQLiteFileSystem::getDatabaseFileSize(const std::string& fileName)
{
    long long size;
    return getFileSize(fileName, size) ? size : 0;
}

std::string SQLiteFileSystem::pathByAppendingComponent(const std::string& path, const std::string& component)
{
    if (path.length() && path.at(path.length()-1) == '/')
        return path + component;
    return path + "/" + component;
}

