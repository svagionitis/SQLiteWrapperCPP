/*
 * Copyright (C) 2007 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "DatabaseAuthorizer.h"

#include <string.h>
#include <iostream>
#include <memory>

std::shared_ptr<DatabaseAuthorizer> DatabaseAuthorizer::create(const std::string& databaseInfoTableName)
{
    return std::shared_ptr<DatabaseAuthorizer>(new DatabaseAuthorizer(databaseInfoTableName));
}

DatabaseAuthorizer::DatabaseAuthorizer(const std::string& databaseInfoTableName)
    : m_securityEnabled(false)
    , m_databaseInfoTableName(databaseInfoTableName)
{
    reset();
    addWhitelistedFunctions();
}

void DatabaseAuthorizer::reset()
{
    m_lastActionWasInsert = false;
    m_lastActionChangedDatabase = false;
    m_permissions = ReadWriteMask;
}

void DatabaseAuthorizer::resetDeletes()
{
    m_hadDeletes = false;
}

void DatabaseAuthorizer::addWhitelistedFunctions()
{
    // SQLite functions used to help implement some operations
    // ALTER TABLE helpers
    m_whitelistedFunctions.insert("sqlite_rename_table");
    m_whitelistedFunctions.insert("sqlite_rename_trigger");
    // GLOB helpers
    m_whitelistedFunctions.insert("glob");

    // SQLite core functions
    m_whitelistedFunctions.insert("abs");
    m_whitelistedFunctions.insert("changes");
    m_whitelistedFunctions.insert("coalesce");
    m_whitelistedFunctions.insert("glob");
    m_whitelistedFunctions.insert("ifnull");
    m_whitelistedFunctions.insert("hex");
    m_whitelistedFunctions.insert("last_insert_rowid");
    m_whitelistedFunctions.insert("length");
    m_whitelistedFunctions.insert("like");
    m_whitelistedFunctions.insert("lower");
    m_whitelistedFunctions.insert("ltrim");
    m_whitelistedFunctions.insert("max");
    m_whitelistedFunctions.insert("min");
    m_whitelistedFunctions.insert("nullif");
    m_whitelistedFunctions.insert("quote");
    m_whitelistedFunctions.insert("replace");
    m_whitelistedFunctions.insert("round");
    m_whitelistedFunctions.insert("rtrim");
    m_whitelistedFunctions.insert("soundex");
    m_whitelistedFunctions.insert("sqlite_source_id");
    m_whitelistedFunctions.insert("sqlite_version");
    m_whitelistedFunctions.insert("substr");
    m_whitelistedFunctions.insert("total_changes");
    m_whitelistedFunctions.insert("trim");
    m_whitelistedFunctions.insert("typeof");
    m_whitelistedFunctions.insert("upper");
    m_whitelistedFunctions.insert("zeroblob");

    // SQLite date and time functions
    m_whitelistedFunctions.insert("date");
    m_whitelistedFunctions.insert("time");
    m_whitelistedFunctions.insert("datetime");
    m_whitelistedFunctions.insert("julianday");
    m_whitelistedFunctions.insert("strftime");

    // SQLite aggregate functions
    // max() and min() are already in the list
    m_whitelistedFunctions.insert("avg");
    m_whitelistedFunctions.insert("count");
    m_whitelistedFunctions.insert("group_concat");
    m_whitelistedFunctions.insert("sum");
    m_whitelistedFunctions.insert("total");

    // SQLite FTS functions
    m_whitelistedFunctions.insert("match");
    m_whitelistedFunctions.insert("snippet");
    m_whitelistedFunctions.insert("offsets");
    m_whitelistedFunctions.insert("optimize");

    // SQLite ICU functions
    // like(), lower() and upper() are already in the list
    m_whitelistedFunctions.insert("regexp");
}

int DatabaseAuthorizer::createTable(const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createTempTable(const std::string& tableName)
{
    // SQLITE_CREATE_TEMP_TABLE results in a UPDATE operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_CREATE_TEMP_TABLE in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropTable(const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropTempTable(const std::string& tableName)
{
    // SQLITE_DROP_TEMP_TABLE results in a DELETE operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_DROP_TEMP_TABLE in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowAlterTable(const std::string&, const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createIndex(const std::string&, const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createTempIndex(const std::string&, const std::string& tableName)
{
    // SQLITE_CREATE_TEMP_INDEX should result in a UPDATE or INSERT operation,
    // which is not allowed in read-only transactions or private browsing,
    // so we might as well disallow SQLITE_CREATE_TEMP_INDEX in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropIndex(const std::string&, const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropTempIndex(const std::string&, const std::string& tableName)
{
    // SQLITE_DROP_TEMP_INDEX should result in a DELETE operation, which is
    // not allowed in read-only transactions or private browsing, so we might
    // as well disallow SQLITE_DROP_TEMP_INDEX in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createTrigger(const std::string&, const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createTempTrigger(const std::string&, const std::string& tableName)
{
    // SQLITE_CREATE_TEMP_TRIGGER results in a INSERT operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_CREATE_TEMP_TRIGGER in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropTrigger(const std::string&, const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropTempTrigger(const std::string&, const std::string& tableName)
{
    // SQLITE_DROP_TEMP_TRIGGER results in a DELETE operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_DROP_TEMP_TRIGGER in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::createView(const std::string&)
{
    return (!allowWrite() ? SQLAuthDeny : SQLAuthAllow);
}

int DatabaseAuthorizer::createTempView(const std::string&)
{
    // SQLITE_CREATE_TEMP_VIEW results in a UPDATE operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_CREATE_TEMP_VIEW in these cases
    return (!allowWrite() ? SQLAuthDeny : SQLAuthAllow);
}

int DatabaseAuthorizer::dropView(const std::string&)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_hadDeletes = true;
    return SQLAuthAllow;
}

int DatabaseAuthorizer::dropTempView(const std::string&)
{
    // SQLITE_DROP_TEMP_VIEW results in a DELETE operation, which is not
    // allowed in read-only transactions or private browsing, so we might as
    // well disallow SQLITE_DROP_TEMP_VIEW in these cases
    if (!allowWrite())
        return SQLAuthDeny;

    m_hadDeletes = true;
    return SQLAuthAllow;
}

int DatabaseAuthorizer::createVTable(const std::string& tableName, const std::string& moduleName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    // Allow only the FTS3 extension
    if (!strcasecmp(moduleName.c_str(), "fts3"))
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::dropVTable(const std::string& tableName, const std::string& moduleName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    // Allow only the FTS3 extension
    if (!strcasecmp(moduleName.c_str(), "fts3"))
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowDelete(const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    return updateDeletesBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowInsert(const std::string& tableName)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    m_lastActionWasInsert = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowUpdate(const std::string& tableName, const std::string&)
{
    if (!allowWrite())
        return SQLAuthDeny;

    m_lastActionChangedDatabase = true;
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowTransaction()
{
    return m_securityEnabled ? SQLAuthDeny : SQLAuthAllow;
}

int DatabaseAuthorizer::allowRead(const std::string& tableName, const std::string&)
{
    if (m_permissions & NoAccessMask && m_securityEnabled)
        return SQLAuthDeny;

    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowReindex(const std::string&)
{
    return (!allowWrite() ? SQLAuthDeny : SQLAuthAllow);
}

int DatabaseAuthorizer::allowAnalyze(const std::string& tableName)
{
    return denyBasedOnTableName(tableName);
}

int DatabaseAuthorizer::allowPragma(const std::string&, const std::string&)
{
    return m_securityEnabled ? SQLAuthDeny : SQLAuthAllow;
}

int DatabaseAuthorizer::allowAttach(const std::string&)
{
    return m_securityEnabled ? SQLAuthDeny : SQLAuthAllow;
}

int DatabaseAuthorizer::allowDetach(const std::string&)
{
    return m_securityEnabled ? SQLAuthDeny : SQLAuthAllow;
}

int DatabaseAuthorizer::allowFunction(const std::string& functionName)
{
    if (m_securityEnabled && !m_whitelistedFunctions.count(functionName))
        return SQLAuthDeny;

    return SQLAuthAllow;
}

void DatabaseAuthorizer::disable()
{
    m_securityEnabled = false;
}

void DatabaseAuthorizer::enable()
{
    m_securityEnabled = true;
}

bool DatabaseAuthorizer::allowWrite()
{
    return !(m_securityEnabled && (m_permissions & ReadOnlyMask || m_permissions & NoAccessMask));
}

void DatabaseAuthorizer::setReadOnly()
{
    m_permissions |= ReadOnlyMask;
}

void DatabaseAuthorizer::setPermissions(int permissions)
{
    m_permissions = permissions;
}

int DatabaseAuthorizer::denyBasedOnTableName(const std::string& tableName) const
{
    if (!m_securityEnabled)
        return SQLAuthAllow;

    // Sadly, normal creates and drops end up affecting sqlite_master in an authorizer callback, so
    // it will be tough to enforce all of the following policies
    // equalIgnoringCase == strcasecmp
    //if (equalIgnoringCase(tableName, "sqlite_master") || equalIgnoringCase(tableName, "sqlite_temp_master") ||
    //    equalIgnoringCase(tableName, "sqlite_sequence") || equalIgnoringCase(tableName, Database::databaseInfoTableName()))
    //        return SQLAuthDeny;

    if (!strcasecmp(tableName.c_str(), m_databaseInfoTableName.c_str()))
        return SQLAuthDeny;

    return SQLAuthAllow;
}

int DatabaseAuthorizer::updateDeletesBasedOnTableName(const std::string& tableName)
{
    int allow = denyBasedOnTableName(tableName);
    if (allow)
        m_hadDeletes = true;
    return allow;
}
