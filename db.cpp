#include "db.h"
#include "log.h"
#include <mutex>

// 一个 PGconn 同一时刻只能被一个线程使用（libpq 内部不带锁）。
// 锁放在这一层，调用方就完全不用操心线程安全。
static std::mutex g_db_mtx;

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

        -- ★ 为什么 hash 用 TEXT 而不是 CHAR(64)：
        --   CHAR(n) 是空格填充的。存一个 40 字符的 SHA-1 进去，
        --   取出来会变成 64 字符（后面补 20 个空格），
        --   前端拿这个带空格的串去拼 URL 就 404 了。
        --   "存进去和取出来不是同一个字符串"的列，是 bug 的温床。
        --
        --   在 PostgreSQL 里 TEXT 和 VARCHAR 性能完全一样，
        --   长度限制应该写成 CHECK 约束，而不是靠类型系统。
        --
        --   这一句是为了把已经建好的旧表掰过来。真实项目里不这么干 ——
        --   每次启动都 ALTER 会重写整张表，那是数据库迁移工具该做的事。
        ALTER TABLE files ALTER COLUMN hash TYPE TEXT;

        -- 一个用户对同一个 hash 只能有一条记录。
        -- 必须是 UNIQUE 索引（不是普通索引），ON CONFLICT (owner_id, hash) 才有依据。
        CREATE UNIQUE INDEX IF NOT EXISTS uniq_files_owner_hash
            ON files(owner_id, hash);

        -- 复合索引的最左列就是 owner_id，所以原来单独给 owner_id
        -- 建的那条索引彻底冗余了（按 owner_id 查也能用新索引），删掉。
        DROP INDEX IF EXISTS idx_files_owner;
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
     std::lock_guard<std::mutex> lk(g_db_mtx);
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
