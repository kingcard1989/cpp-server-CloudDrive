#pragma once
#include <libpq-fe.h>
#include <string>



// 预置演示账号。幂等：重复调用不会重复插入，也不会覆盖已改过的密码。
bool user_seed(PGconn* conn);

// 校验用户名 + 明文密码。通过则把 users.id 写进 uid 并返回 true。
bool user_check(PGconn* conn, const std::string& user,
                const std::string& pwd, long long& uid);
