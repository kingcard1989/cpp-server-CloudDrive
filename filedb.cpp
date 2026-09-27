#include "filedb.h"
#include "db.h"
#include "log.h"

bool filedb_add(PGconn* conn, long long ownerId, const std::string& hash,
                const std::string& name, long long size,
                int chunkSize, int chunkCount) {
    // ON CONFLICT DO NOTHING 的依据是 uniq_files_owner_hash 那个唯一索引。
    //
    // 为什么不用 DO UPDATE：重复上传同一个文件时不该刷新 created_at，
    // 否则列表按时间排序会出现"文件莫名其妙跳到最前面"。
    PGresult* r = db_exec(conn,
        "INSERT INTO files (owner_id, hash, filename, size, chunk_size, chunk_count) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (owner_id, hash) DO NOTHING",
        { std::to_string(ownerId), hash, name, std::to_string(size),
          std::to_string(chunkSize), std::to_string(chunkCount) });
    if (!r) return false;

    PQclear(r);
    return true;
}

bool filedb_get(PGconn* conn, long long ownerId, const std::string& hash, FileRow& out) {
    // ★ 这个 WHERE 里必须同时有 owner_id 和 hash。
    //   只按 hash 查就等着被越权下载吧 —— 详见 main.cpp 里 handle_download 的注释。
    PGresult* r = db_exec(conn,
        "SELECT filename, size FROM files WHERE owner_id = $1 AND hash = $2",
        { std::to_string(ownerId), hash });
    if (!r) return false;

    bool found = false;
    if (PQntuples(r) == 1) {
        out.hash = hash;
        out.name = PQgetvalue(r, 0, 0);
        out.size = std::stoll(PQgetvalue(r, 0, 1));
        found = true;
    }

    PQclear(r);
    return found;
}

bool filedb_list(PGconn* conn, long long ownerId, std::vector<FileRow>& out) {
    out.clear();

    // 为什么排序要跟一个 id DESC：
    //   now() 返回的是"事务开始时间"，同一个事务里插入的多行 created_at 完全相同。
    //   只按 created_at 排序时，这些并列的行顺序是不确定的 ——
    //   测试里能跑通，换台机器结果就变了。加一个唯一的 id 兜底才稳定。
    PGresult* r = db_exec(conn,
        "SELECT hash, filename, size FROM files WHERE owner_id = $1 "
        "ORDER BY created_at DESC, id DESC",
        { std::to_string(ownerId) });
    if (!r) return false;

    int n = PQntuples(r);
    for (int i = 0; i < n; ++i) {
        FileRow f;
        f.hash = PQgetvalue(r, i, 0);
        f.name = PQgetvalue(r, i, 1);
        f.size = std::stoll(PQgetvalue(r, i, 2));
        out.push_back(f);
    }

    PQclear(r);
    return true;
}

bool filedb_remove(PGconn* conn, long long ownerId, const std::string& hash) {
    PGresult* r = db_exec(conn,
        "DELETE FROM files WHERE owner_id = $1 AND hash = $2",
        { std::to_string(ownerId), hash });
    if (!r) return false;

    // PQcmdTuples 返回"这条命令影响了几行"的字符串。
    // 删到 0 行说明这个文件压根不在你名下 —— 调用方据此回 404。
    bool removed = (std::string(PQcmdTuples(r)) != "0");

    PQclear(r);
    return removed;
}

long long filedb_refcount(PGconn* conn, const std::string& hash) {
    PGresult* r = db_exec(conn,
        "SELECT count(*) FROM files WHERE hash = $1", { hash });
    if (!r) return -1;                    // 查不出来，调用方当作"还有人在用"

    long long n = std::stoll(PQgetvalue(r, 0, 0));
    PQclear(r);
    return n;
}
