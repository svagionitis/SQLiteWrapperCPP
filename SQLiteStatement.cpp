/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include "SQLiteStatement.h"

#include "SQLValue.h"
#include <sqlite3.h>
#include <strings.h>

#include <thread>
#include <algorithm>

#include <glog/logging.h>

// Unicode char as char
#define UChar char

#ifndef NDEBUG
#define ASSERT(x)
#else
#define ASSERT(x) \
         if (! (x)) \
         { \
            std::cout << "ERROR!! Assert " << #x << " failed\n"; \
            std::cout << " on line " << __LINE__  << "\n"; \
            std::cout << " in file " << __FILE__ << "\n";  \
         }
#endif

#ifndef NDEBUG
#define ASSERT_NOT_REACHED()
#else
#define ASSERT_NOT_REACHED() \
         { \
            std::cout << "Assert not reached\n"; \
            std::cout << " on line " << __LINE__  << "\n"; \
            std::cout << " in file " << __FILE__ << "\n";  \
         }
#endif

// SQLite 3.6.16 makes sqlite3_prepare_v2 automatically retry preparing the statement
// once if the database scheme has changed. We rely on this behavior.
#if SQLITE_VERSION_NUMBER < 3006016
#error SQLite version 3.6.16 or newer is required
#endif


SQLiteStatement::SQLiteStatement(SQLiteDatabase& db, const std::string& sql)
    : m_database(db)
    , m_query(sql)
    , m_statement(0)
#ifndef NDEBUG
    , m_isPrepared(false)
#endif
{
}

SQLiteStatement::~SQLiteStatement()
{
    finalize();
}

int SQLiteStatement::prepare()
{
    DLOG(INFO) << __func__ << " >>>";
#ifndef NDEBUG
    ASSERT(!m_isPrepared);
#endif

    std::lock_guard<std::mutex> lock(m_database.databaseMutex());
    if (m_database.isInterrupted())
    {
        DLOG(INFO) << __func__ << " <<< " << "SQLITE_INTERRUPT";
        return SQLITE_INTERRUPT;
    }

    //CString query = m_query.stripWhiteSpace().utf8();
    std::string query = m_query;
    //query.erase(std::remove_if(query.begin(), query.end(), ::isspace), query.end());

    DLOG(INFO) << "SQL - prepare - " << query.data();

    // Pass the length of the string including the null character to sqlite3_prepare_v2;
    // this lets SQLite avoid an extra string copy.
    size_t lengthIncludingNullCharacter = query.length() + 1;

    const char* tail;
    int error = sqlite3_prepare_v2(m_database.sqlite3Handle(), query.data(), lengthIncludingNullCharacter, &m_statement, &tail);

    if (error != SQLITE_OK)
        LOG(ERROR) << "sqlite3_prepare16 failed " << "(" << error << ")\n" << query.data() << "\n" << sqlite3_errmsg(m_database.sqlite3Handle());

    if (tail && *tail)
        error = SQLITE_ERROR;

#ifndef NDEBUG
    m_isPrepared = error == SQLITE_OK;
#endif
    DLOG(INFO) << __func__ << " <<< " << ((error == SQLITE_OK) ? "OK" : "ERROR");
    return error;
}

int SQLiteStatement::step()
{
    DLOG(INFO) << __func__ << " >>>";
    std::lock_guard<std::mutex> lock(m_database.databaseMutex());
    if (m_database.isInterrupted())
    {
        DLOG(INFO) << __func__ << " <<< " << "SQLITE_INTERRUPT";
        return SQLITE_INTERRUPT;
    }
#ifndef NDEBUG
    //ASSERT(m_isPrepared);
#endif

    if (!m_statement)
    {
        DLOG(INFO) << __func__ << " <<< " << "SQLITE_OK";
        return SQLITE_OK;
    }

    // The database needs to update its last changes count before each statement
    // in order to compute properly the lastChanges() return value.
    m_database.updateLastChangesCount();

    DLOG(INFO) << "SQL - step - " << m_query.data();
    int error = sqlite3_step(m_statement);
    if (error != SQLITE_DONE && error != SQLITE_ROW) {
        LOG(ERROR) << "sqlite3_step failed (" << error << ")\nQuery - " << m_query.data() << "\nError - " << sqlite3_errmsg(m_database.sqlite3Handle());
    }

    DLOG(INFO) << __func__ << " <<< " << ((error == SQLITE_OK) ? "OK" : "ERROR");
    return error;
}

int SQLiteStatement::finalize()
{
    DLOG(INFO) << __func__ << " >>>";
#ifndef NDEBUG
    m_isPrepared = false;
#endif
    if (!m_statement)
    {
        DLOG(INFO) << __func__ << " <<< " << "SQLITE_OK";
        return SQLITE_OK;
    }
    DLOG(INFO) << "SQL - finalize - " << m_query.data();
    int result = sqlite3_finalize(m_statement);
    m_statement = 0;
    DLOG(INFO) << __func__ << " <<< " << "result=" << result;
    return result;
}

int SQLiteStatement::reset()
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    if (!m_statement)
        return SQLITE_OK;
    DLOG(INFO) << "SQL - reset - " << m_query.data();
    return sqlite3_reset(m_statement);
}

bool SQLiteStatement::executeCommand()
{
    if (!m_statement && prepare() != SQLITE_OK)
        return false;
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    if (step() != SQLITE_DONE) {
        finalize();
        return false;
    }
    finalize();
    return true;
}

bool SQLiteStatement::returnsAtLeastOneResult()
{
    if (!m_statement && prepare() != SQLITE_OK)
        return false;
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    if (step() != SQLITE_ROW) {
        finalize();
        return false;
    }
    finalize();
    return true;

}

int SQLiteStatement::bindBlob(int index, const void* blob, int size)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());
    ASSERT(blob);
    ASSERT(size >= 0);

    if (!m_statement)
        return SQLITE_ERROR;

    return sqlite3_bind_blob(m_statement, index, blob, size, SQLITE_TRANSIENT);
}

int SQLiteStatement::bindBlob(int index, const std::string& text)
{
    // String::characters() returns 0 for the empty string, which SQLite
    // treats as a null, so we supply a non-null pointer for that case.
    UChar anyCharacter = 0;
    const UChar* characters;
    if (!text.length())
        characters = &anyCharacter;
    else
        //characters = text.characters();
        characters = text.data();

    return bindBlob(index, characters, text.length() * sizeof(UChar));
}

int SQLiteStatement::bindText(int index, const std::string& text)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());

    // String::characters() returns 0 for the empty string, which SQLite
    // treats as a null, so we supply a non-null pointer for that case.
    UChar anyCharacter = 0;
    const UChar* characters;
    if (!text.length())
        characters = &anyCharacter;
    else
        //characters = text.characters();
        characters = text.data();

    return sqlite3_bind_text16(m_statement, index, characters, sizeof(UChar) * text.length(), SQLITE_TRANSIENT);
}

int SQLiteStatement::bindInt(int index, int integer)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());

    return sqlite3_bind_int(m_statement, index, integer);
}

int SQLiteStatement::bindInt64(int index, int64_t integer)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());

    return sqlite3_bind_int64(m_statement, index, integer);
}

int SQLiteStatement::bindDouble(int index, double number)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());

    return sqlite3_bind_double(m_statement, index, number);
}

int SQLiteStatement::bindNull(int index)
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    ASSERT(index > 0);
    ASSERT(static_cast<unsigned>(index) <= bindParameterCount());

    return sqlite3_bind_null(m_statement, index);
}

int SQLiteStatement::bindValue(int index, const SQLValue& value)
{
    switch (value.type()) {
        case SQLValue::StringValue:
            return bindText(index, value.string());
        case SQLValue::NumberValue:
            return bindDouble(index, value.number());
        case SQLValue::NullValue:
            return bindNull(index);
    }

    ASSERT_NOT_REACHED();
    return SQLITE_ERROR;
}

unsigned SQLiteStatement::bindParameterCount() const
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    if (!m_statement)
        return 0;
    return sqlite3_bind_parameter_count(m_statement);
}

int SQLiteStatement::columnCount()
{
#ifndef NDEBUG
    ASSERT(m_isPrepared);
#endif
    if (!m_statement)
        return 0;
    return sqlite3_data_count(m_statement);
}

bool SQLiteStatement::isColumnNull(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return false;
    if (columnCount() <= col)
        return false;

    return sqlite3_column_type(m_statement, col) == SQLITE_NULL;
}

bool SQLiteStatement::isColumnDeclaredAsBlob(int col)
{
    ASSERT(col >= 0);
    if (!m_statement) {
        if (prepare() != SQLITE_OK)
            return false;
    }

    return !strcasecmp(std::string("BLOB").c_str(), std::string(reinterpret_cast<const UChar*>(sqlite3_column_decltype16(m_statement, col))).c_str()) ? true : false;
}

std::string SQLiteStatement::getColumnName(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return std::string();
    if (columnCount() <= col)
        return std::string();
    return std::string(reinterpret_cast<const UChar*>(sqlite3_column_name16(m_statement, col)));
}

SQLValue SQLiteStatement::getColumnValue(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return SQLValue();
    if (columnCount() <= col)
        return SQLValue();

    // SQLite is typed per value. optional column types are
    // "(mostly) ignored"
    sqlite3_value* value = sqlite3_column_value(m_statement, col);
    switch (sqlite3_value_type(value)) {
        case SQLITE_INTEGER:    // SQLValue and JS don't represent integers, so use FLOAT -case
        case SQLITE_FLOAT:
            return SQLValue(sqlite3_value_double(value));
        case SQLITE_BLOB:       // SQLValue and JS don't represent blobs, so use TEXT -case
        case SQLITE_TEXT: {
            const UChar* string = reinterpret_cast<const UChar*>(sqlite3_value_text16(value));
            return SQLValue(std::string(string));
        }
        case SQLITE_NULL:
            return SQLValue();
        default:
            break;
    }
    ASSERT_NOT_REACHED();
    return SQLValue();
}

std::string SQLiteStatement::getColumnText(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return std::string();
    if (columnCount() <= col)
        return std::string();
    return std::string(reinterpret_cast<const UChar*>(sqlite3_column_text16(m_statement, col)), sqlite3_column_bytes16(m_statement, col) / sizeof(UChar));
}

double SQLiteStatement::getColumnDouble(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return 0.0;
    if (columnCount() <= col)
        return 0.0;
    return sqlite3_column_double(m_statement, col);
}

int SQLiteStatement::getColumnInt(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return 0;
    if (columnCount() <= col)
        return 0;
    return sqlite3_column_int(m_statement, col);
}

int64_t SQLiteStatement::getColumnInt64(int col)
{
    ASSERT(col >= 0);
    if (!m_statement)
        if (prepareAndStep() != SQLITE_ROW)
            return 0;
    if (columnCount() <= col)
        return 0;
    return sqlite3_column_int64(m_statement, col);
}

std::string SQLiteStatement::getColumnBlobAsString(int col)
{
    ASSERT(col >= 0);

    if (!m_statement && prepareAndStep() != SQLITE_ROW)
        return std::string();

    if (columnCount() <= col)
        return std::string();

    const void* blob = sqlite3_column_blob(m_statement, col);
    if (!blob)
        return std::string();

    int size = sqlite3_column_bytes(m_statement, col);
    if (size < 0)
        return std::string();

    ASSERT(!(size % sizeof(UChar)));
    return std::string(static_cast<const UChar*>(blob), size / sizeof(UChar));
}

void SQLiteStatement::getColumnBlobAsVector(int col, std::vector<char>& result)
{
    ASSERT(col >= 0);

    if (!m_statement && prepareAndStep() != SQLITE_ROW) {
        result.clear();
        return;
    }

    if (columnCount() <= col) {
        result.clear();
        return;
    }

    const void* blob = sqlite3_column_blob(m_statement, col);
    if (!blob) {
        result.clear();
        return;
    }

    int size = sqlite3_column_bytes(m_statement, col);
    result.resize((size_t)size);
    for (int i = 0; i < size; ++i)
        result[i] = (static_cast<const unsigned char*>(blob))[i];
}

const void* SQLiteStatement::getColumnBlob(int col, int& size)
{
    ASSERT(col >= 0);

    size = 0;

    if (finalize() != SQLITE_OK)
        DLOG(INFO) << "Finalize failed";
    if (prepare() != SQLITE_OK) {
        DLOG(INFO) << "Prepare failed";
        return 0;
    }
    if (step() != SQLITE_ROW) {
        DLOG(INFO) << "Step wasn't a row";
        return 0;
    }

    if (columnCount() <= col)
        return 0;

    const void* blob = sqlite3_column_blob(m_statement, col);
    if (!blob)
        return 0;

    size = sqlite3_column_bytes(m_statement, col);
    return blob;
}

bool SQLiteStatement::returnTextResults(int col, std::vector<std::string>& v)
{
    ASSERT(col >= 0);

    v.clear();

    if (m_statement)
        finalize();
    if (prepare() != SQLITE_OK)
        return false;

    while (step() == SQLITE_ROW)
        v.push_back(getColumnText(col));
    bool result = true;
    if (m_database.lastError() != SQLITE_DONE) {
        result = false;
        DLOG(INFO) << "Error reading results from database query " << m_query.data();
    }
    finalize();
    return result;
}

bool SQLiteStatement::returnIntResults(int col, std::vector<int>& v)
{
    v.clear();

    if (m_statement)
        finalize();
    if (prepare() != SQLITE_OK)
        return false;

    while (step() == SQLITE_ROW)
        v.push_back(getColumnInt(col));
    bool result = true;
    if (m_database.lastError() != SQLITE_DONE) {
        result = false;
        DLOG(INFO) << "Error reading results from database query " << m_query.data();
    }
    finalize();
    return result;
}

bool SQLiteStatement::returnInt64Results(int col, std::vector<int64_t>& v)
{
    v.clear();

    if (m_statement)
        finalize();
    if (prepare() != SQLITE_OK)
        return false;

    while (step() == SQLITE_ROW)
        v.push_back(getColumnInt64(col));
    bool result = true;
    if (m_database.lastError() != SQLITE_DONE) {
        result = false;
        DLOG(INFO) << "Error reading results from database query " << m_query.data();
    }
    finalize();
    return result;
}

bool SQLiteStatement::returnDoubleResults(int col, std::vector<double>& v)
{
    v.clear();

    if (m_statement)
        finalize();
    if (prepare() != SQLITE_OK)
        return false;

    while (step() == SQLITE_ROW)
        v.push_back(getColumnDouble(col));
    bool result = true;
    if (m_database.lastError() != SQLITE_DONE) {
        result = false;
        DLOG(INFO) << "Error reading results from database query " << m_query.data();
    }
    finalize();
    return result;
}

bool SQLiteStatement::isExpired()
{
    return !m_statement || sqlite3_expired(m_statement);
}

