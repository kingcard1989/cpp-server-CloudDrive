#include "user.h"
#include "db.h"
#include "auth.h"
#include "log.h"

// 演示账号 —— 密码是公开的，就是为了让面试官能直接登录看效果。
// 真实项目里没有这个函数，账号是注册流程写进去的。
//
// 为什么要写成代码、而不是手工 INSERT：
//   面试官 clone 仓库时，.env 没提交、数据库也没提交，他跑起来库里是空的。
//   账号必须由程序自己造出来，否则项目在别人机器上根本演示不了。
struct SeedUser { const char* name; const char* pwd; const char* salt; };

static const SeedUser kSeed[] = {
    { "alice", "alice123", "9f2c1b7a4e6d8053" },
    { "bob",   "bob123",   "3a7e0d5c8b1f2946" },
};

bool user_seed(PGconn* conn) {
    for (const auto& s : kSeed) {
        std::string hash = auth_hash_pwd(s.pwd, s.salt);
        if (hash.empty()) {
            log_line("[user] 预置账号失败：哈希计算出错");
            return false;
        }

        // ON CONFLICT DO NOTHING 让它幂等：服务器每次启动都会跑这里，
        // 没有它第二次启动就会撞上 username 的 UNIQUE 约束。
        //
        // 也不能写成 DO UPDATE —— 那等于每次重启都把密码重置回去，
        // 你在演示中途改过的密码就白改了。
        PGresult* r = db_exec(conn,
            "INSERT INTO users (username, pwd_hash, pwd_salt) "
            "VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
            { s.name, hash, s.salt });
        if (!r) return false;

        PQclear(r);
        log_line(std::string("[user] 预置账号就绪: ") + s.name);
    }
    return true;
}

bool user_check(PGconn* conn, const std::string& user,
                const std::string& pwd, long long& uid) {
    PGresult* r = db_exec(conn,
        "SELECT id, pwd_hash, pwd_salt FROM users WHERE username = $1", { user });
    if (!r) return false;

    bool ok = false;
    if (PQntuples(r) == 1) {
        long long   id   = std::stoll(PQgetvalue(r, 0, 0));
        std::string hash = PQgetvalue(r, 0, 1);
        std::string salt = PQgetvalue(r, 0, 2);

        if (secure_equal(auth_hash_pwd(pwd, salt), hash)) {
            uid = id;
            ok  = true;
        }
    } else {
        // ★ 用户不存在也要空算一次哈希。
        //   否则「秒回=用户不存在、慢=用户存在」，攻击者靠响应时间就能
        //   枚举出系统里有哪些用户名（用户枚举攻击）。
        auth_hash_pwd(pwd, "0000000000000000");
    }

    PQclear(r);
    return ok;
}
