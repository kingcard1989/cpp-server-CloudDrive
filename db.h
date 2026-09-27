#pragma once
#include <libpq-fe.h>
#include <string>
PGconn* db_connect(const std:: string& conninfo );
void db_close(PGconn* conn);