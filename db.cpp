#include "db.h"
#include "log.h"
using namespace std;
PGconn* db_connect(const string& conninfo){
    PGconn* conn  = PQconnectdb(conninfo.c_str());
    if(PQstatus(conn)!=CONNECTION_OK){
    log_line(string("[db] 连接失败: ") + PQerrorMessage(conn));
    PQfinish(conn);
    return nullptr;
    }
    log_line("successdbconn");
    return conn;

}
void db_close(PGconn* conn){
if(conn) PQfinish(conn);
}
bool db_init(PGconn* conn) {
    static const char* SQL = R"SQL(
        CREATE TABLE IF NOT EXISTS users (
            id          BIGSERIAL   PRIMARY KEY,
            username    TEXT        NOT NULL UNIQUE,
            pwd_hash    TEXT        NOT NULL,
            pwd_salt    TEXT        NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS files (
            id          BIGSERIAL   PRIMARY KEY,
            owner_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            hash        CHAR(64)    NOT NULL,
            filename    TEXT        NOT NULL,
            size        BIGINT      NOT NULL,
            chunk_size  INTEGER     NOT NULL,
            chunk_count INTEGER     NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
    )SQL";

    PGresult* res = PQexec(conn, SQL);
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    if (!ok) {
        log_line(std::string("[db] 建表失败: ") + PQerrorMessage(conn));
    }
    PQclear(res);
    return ok;
}
PGresult* db_exec(PGconn* conn, const char* sql, const std::vector<std::string>& params) {
    std::vector<const char*> raw;
    raw.reserve(params.size());
    for (const auto& p : params) raw.push_back(p.c_str());

    PGresult* res = PQexecParams(conn, sql,
                                 static_cast<int>(raw.size()), nullptr,
                                 raw.empty() ? nullptr : raw.data(),
                                 nullptr, nullptr, 0);

    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
        log_line(std::string("[db] 查询失败: ") + PQerrorMessage(conn));
        PQclear(res);
        return nullptr;
    }
    return res;
}
