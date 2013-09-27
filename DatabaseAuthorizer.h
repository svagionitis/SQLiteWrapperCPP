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
#ifndef DatabaseAuthorizer_h
#define DatabaseAuthorizer_h

#include <iostream>
#include <memory>
#include <functional>
#include <unordered_set>

extern const int SQLAuthAllow;
extern const int SQLAuthIgnore;
extern const int SQLAuthDeny;

class DatabaseAuthorizer {
public:

    enum Permissions {
        ReadWriteMask = 0,
        ReadOnlyMask = 1 << 1,
        NoAccessMask = 1 << 2
    };

    static std::shared_ptr<DatabaseAuthorizer> create(const std::string& databaseInfoTableName);

    int createTable(const std::string& tableName);
    int createTempTable(const std::string& tableName);
    int dropTable(const std::string& tableName);
    int dropTempTable(const std::string& tableName);
    int allowAlterTable(const std::string& databaseName, const std::string& tableName);

    int createIndex(const std::string& indexName, const std::string& tableName);
    int createTempIndex(const std::string& indexName, const std::string& tableName);
    int dropIndex(const std::string& indexName, const std::string& tableName);
    int dropTempIndex(const std::string& indexName, const std::string& tableName);

    int createTrigger(const std::string& triggerName, const std::string& tableName);
    int createTempTrigger(const std::string& triggerName, const std::string& tableName);
    int dropTrigger(const std::string& triggerName, const std::string& tableName);
    int dropTempTrigger(const std::string& triggerName, const std::string& tableName);

    int createView(const std::string& viewName);
    int createTempView(const std::string& viewName);
    int dropView(const std::string& viewName);
    int dropTempView(const std::string& viewName);

    int createVTable(const std::string& tableName, const std::string& moduleName);
    int dropVTable(const std::string& tableName, const std::string& moduleName);

    int allowDelete(const std::string& tableName);
    int allowInsert(const std::string& tableName);
    int allowUpdate(const std::string& tableName, const std::string& columnName);
    int allowTransaction();

    int allowSelect() { return SQLAuthAllow; }
    int allowRead(const std::string& tableName, const std::string& columnName);

    int allowReindex(const std::string& indexName);
    int allowAnalyze(const std::string& tableName);
    int allowFunction(const std::string& functionName);
    int allowPragma(const std::string& pragmaName, const std::string& firstArgument);

    int allowAttach(const std::string& filename);
    int allowDetach(const std::string& databaseName);

    void disable();
    void enable();
    void setReadOnly();
    void setPermissions(int permissions);

    void reset();
    void resetDeletes();

    bool lastActionWasInsert() const { return m_lastActionWasInsert; }
    bool lastActionChangedDatabase() const { return m_lastActionChangedDatabase; }
    bool hadDeletes() const { return m_hadDeletes; }

private:
    explicit DatabaseAuthorizer(const std::string& databaseInfoTableName);
    void addWhitelistedFunctions();
    int denyBasedOnTableName(const std::string&) const;
    int updateDeletesBasedOnTableName(const std::string&);
    bool allowWrite();

    int m_permissions;
    bool m_securityEnabled : 1;
    bool m_lastActionWasInsert : 1;
    bool m_lastActionChangedDatabase : 1;
    bool m_hadDeletes : 1;

    const std::string m_databaseInfoTableName;

    std::unordered_set<std::string> m_whitelistedFunctions;
};

#endif // DatabaseAuthorizer_h
