#pragma once
#include <libpq-fe.h>
#include <string>
PGconn* db_connect(const std:: string& conninfo );
void db_close(PGconn* conn);
bool db_init(PGconn* conn);
#include <vector>

// 执行带参数的 SQL。成功返回 PGresult*（**调用方负责 PQclear**），失败返回 nullptr 并已打日志。
PGresult* db_exec(PGconn* conn, const char* sql, const std::vector<std::string>& params);
