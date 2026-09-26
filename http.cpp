#include "http.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>

// ==================== 解析 ====================

bool parse_request_line(const std::string& raw, HttpRequest& req) {
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return false;

    std::string line = raw.substr(0, line_end);   // 形如 "GET /upload?a=1 HTTP/1.1"

    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    req.method  = line.substr(0, sp1);
    std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = line.substr(sp2 + 1);

    size_t q = target.find('?');
    if (q == std::string::npos) {
        req.path = target;
    } else {
        req.path  = target.substr(0, q);
        req.query = target.substr(q + 1);
    }
    return true;
}

void parse_headers(const std::string& raw, HttpRequest& req) {
    size_t pos = raw.find("\r\n");
    if (pos == std::string::npos) return;
    pos += 2;

    while (true) {
        size_t end = raw.find("\r\n", pos);
        if (end == std::string::npos) break;
        if (end == pos) break;                  // 空行 = 请求头结束

        std::string line = raw.substr(pos, end - pos);
        pos = end + 2;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);

        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        size_t s = val.find_first_not_of(" \t");
        val = (s == std::string::npos) ? "" : val.substr(s);

        req.headers[key] = val;
    }
}

std::string body_so_far(const std::string& raw) {
    size_t p = raw.find("\r\n\r\n");
    if (p == std::string::npos) return std::string();
    return raw.substr(p + 4);
}

std::string header_of(const HttpRequest& req, const std::string& lower_name) {
    auto it = req.headers.find(lower_name);
    return (it == req.headers.end()) ? std::string() : it->second;
}

uint64_t header_num(const HttpRequest& req, const std::string& lower_name) {
    std::string v = header_of(req, lower_name);
    uint64_t n = 0;
    for (char c : v) {
        if (c < '0' || c > '9') break;          // 遇到非数字就停
        n = n * 10 + static_cast<uint64_t>(c - '0');
    }
    return n;
}

std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());

    auto hex_val = [](char h) -> int {
        if (h >= '0' && h <= '9') return h - '0';
        if (h >= 'a' && h <= 'f') return h - 'a' + 10;
        if (h >= 'A' && h <= 'F') return h - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '+') { out.push_back(' '); continue; }
        if (c == '%' && i + 2 < s.size()) {
            int hi = hex_val(s[i + 1]);
            int lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>(hi * 16 + lo));
                i += 2;
                continue;
            }
        }
        out.push_back(c);
    }
    return out;
}

std::map<std::string, std::string> parse_query(const std::string& query) {
    std::map<std::string, std::string> out;
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();

        std::string pair = query.substr(pos, amp - pos);
        pos = amp + 1;
        if (pair.empty()) continue;

        size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            out[url_decode(pair)] = "";
        } else {
            out[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
        }
    }
    return out;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

bool parse_range(const std::string& range, uint64_t fileSize,
                 uint64_t& outStart, uint64_t& outEnd) {
    // 只认 "bytes=" 开头的格式，其它一律当不支持
    const std::string prefix = "bytes=";
    if (range.compare(0, prefix.size(), prefix) != 0) return false;
    if (fileSize == 0) return false;

    std::string spec = range.substr(prefix.size());
    size_t dash = spec.find('-');
    if (dash == std::string::npos) return false;

    std::string left  = spec.substr(0, dash);
    std::string right = spec.substr(dash + 1);

    uint64_t start = 0, end = 0;

    if (left.empty()) {
        // "bytes=-500" 表示"最后 500 字节"
        if (right.empty()) return false;
        uint64_t n = std::strtoull(right.c_str(), nullptr, 10);
        if (n == 0) return false;
        if (n > fileSize) n = fileSize;
        start = fileSize - n;
        end   = fileSize - 1;
    } else {
        start = std::strtoull(left.c_str(), nullptr, 10);
        if (right.empty()) {
            end = fileSize - 1;                  // "bytes=100-" 表示从 100 到结尾
        } else {
            end = std::strtoull(right.c_str(), nullptr, 10);
        }
        if (start >= fileSize) return false;
        if (end >= fileSize) end = fileSize - 1;
        if (end < start) return false;
    }

    outStart = start;
    outEnd   = end;
    return true;
}

// ==================== 组装 ====================

std::string build_head(int code, const std::string& status,
                       const std::string& content_type,
                       const std::string& extra_headers) {
    std::string h;
    h += "HTTP/1.1 " + std::to_string(code) + " " + status + "\r\n";
    h += "Content-Type: " + content_type + "\r\n";
    h += "Connection: close\r\n";
    h += extra_headers;
    h += "\r\n";                                 // 空行：头和 body 的分界
    return h;
}

std::string build_response(int code, const std::string& status,
                           const std::string& content_type,
                           const std::string& body,
                           const std::string& extra_headers) {
    std::string extra = "Content-Length: " + std::to_string(body.size()) + "\r\n";
    extra += extra_headers;
    return build_head(code, status, content_type, extra) + body;
}
