#pragma once
#include <string>
#include <map>

// 读 .env
std::map<std::string, std::string> load_env(const std::string& path);

// base64 解码
bool base64_decode(const std::string& in, std::string& out);

// 常量时间比较：耗时只跟长度有关，跟内容无关
bool secure_equal(const std::string& a, const std::string& b);

// PBKDF2-HMAC-SHA256 派生出密码哈希，返回 64 位十六进制串。
// 计算失败返回空串 —— 调用方必须当作「不通过」处理（fail-closed）。
std::string auth_hash_pwd(const std::string& pwd, const std::string& salt);

// 解析 "Basic xxxxx"，拆出用户名和密码
bool auth_parse_basic(const std::string& authorization,
                      std::string& user, std::string& pwd);

// 401 响应头
std::string auth_challenge();

