#include "auth.h"
#include <map>
#include <fstream>
#include "log.h"
static std::string g_user;
static std::string g_pass;

static std::string trim(const std::string&s){
   size_t b = s.find_first_not_of("\t\r\n");
   if(b == std::string::npos) return std::string();
   size_t e = s.find_last_not_of("\t\r\n");
   return s.substr(b,e-b+1);
}
static std::map<std::string, std::string> load_env(const std::string& path) {
    std::map<std::string, std::string> kv;
    std::ifstream in(path);
    if (!in) return kv;                      // 文件不存在，返回空表

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (!key.empty()) kv[key] = val;
    }
    return kv;
}
bool auth_init(const std::string& config_path) {
    auto cfg = load_env(config_path);

    auto u = cfg.find("WP_USER");
    auto p = cfg.find("WP_PASS");
    if (u == cfg.end() || p == cfg.end() ||
        u->second.empty() || p->second.empty()) {
        log_line("[认证] " + config_path + " 里读不到 WP_USER / WP_PASS —— 所有请求一律拒绝");
        return false;
    }

    g_user = u->second;
    g_pass = p->second;
    log_line("[认证] 已加载账号：" + g_user + "（密码长度 " +
             std::to_string(g_pass.size()) + "）");
    return true;
}

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;                               // 非法字符
}
bool base64_decode(const std::string& in, std::string& out) {
    out.clear();
    if (in.empty() || in.size() % 4 != 0) return false;

    // 每 4 个字符一组，还原成 3 个字节。
    // 每个 base64 字符携带 6 位，4×6 = 24 位 = 3 字节，正好对齐。
    for (size_t i = 0; i < in.size(); i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            char c = in[i + k];
            if (c == '=') { v[k] = 0; ++pad; continue; }   // '=' 是填充，值当 0 处理
            v[k] = b64_val(static_cast<unsigned char>(c));
            if (v[k] < 0) return false;
        }

        // 4 段 6 位拼成 24 位
        unsigned n = (static_cast<unsigned>(v[0]) << 18) |
                     (static_cast<unsigned>(v[1]) << 12) |
                     (static_cast<unsigned>(v[2]) <<  6) |
                      static_cast<unsigned>(v[3]);

        out.push_back(static_cast<char>((n >> 16) & 0xFF));
        if (pad < 2) out.push_back(static_cast<char>((n >> 8) & 0xFF));
        if (pad < 1) out.push_back(static_cast<char>( n       & 0xFF));
    }
    return true;
}
static bool secure_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);   // 有任何一位不同，diff 就非 0
    }
    return diff == 0;
}

bool auth_ok(const std::string& authorization) {
    const std::string prefix = "Basic ";
    if (authorization.size() <= prefix.size()) return false;
    if (authorization.compare(0, prefix.size(), prefix) != 0) return false;

    std::string decoded;
    if (!base64_decode(authorization.substr(prefix.size()), decoded)) return false;

    size_t colon = decoded.find(':');        // 格式固定是 "用户名:密码"
    if (colon == std::string::npos) return false;

    std::string user = decoded.substr(0, colon);
    std::string pass = decoded.substr(colon + 1);

    // 故意分开算再合并：如果写成 if (!okUser) return false，
    // 用户名一错就跳过了密码比较，又给时序攻击留了缝。
    bool okUser = secure_equal(user, g_user);
    bool okPass = secure_equal(pass, g_pass);
    return okUser && okPass;
}

std::string auth_challenge() {
    // realm 会显示在浏览器弹框上。这里用纯 ASCII 是有意的 ——
    // HTTP 头按规范是 ISO-8859-1，塞中文各家浏览器表现不一致。
    return "WWW-Authenticate: Basic realm=\"WangPan\", charset=\"UTF-8\"\r\n";
}