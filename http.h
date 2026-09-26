#pragma once
#include <string>
#include <map>
#include <cstdint>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string query;                            // URL 里 ? 之后的部分（已切出来，未解码）
    std::string version;
    std::map<std::string, std::string> headers;   // 键统一小写
    std::string body;                             // 由调用方填充，解析层不负责收
};

// ============ 解析（纯字符串操作，不碰 socket）============

bool parse_request_line(const std::string& raw, HttpRequest& req);
void parse_headers(const std::string& raw, HttpRequest& req);

// 取 raw 中 "\r\n\r\n" 之后的字节。
//
// ★★★ 这是第5课埋的那个坑 ★★★
// recv_headers 是一口气往缓冲区里收字节的，它看到 \r\n\r\n 就停，
// 但那一批字节里往往已经"搭便车"带上了 body 的开头。
// 如果你只解析请求头、把 raw 剩下的部分扔掉，
// body 的前几 KB 就会凭空消失，上传的文件开头会变成一堆 0。
// 分片上传时每片只有 1MB，这种情况几乎必然发生。
std::string body_so_far(const std::string& raw);

std::string header_of(const HttpRequest& req, const std::string& lower_name);
uint64_t    header_num(const HttpRequest& req, const std::string& lower_name);

// "a=1&b=2" → {a:1, b:2}，值做过 URL 解码
std::map<std::string, std::string> parse_query(const std::string& query);
std::string url_decode(const std::string& s);

// 把字符串转义成可以安全放进 JSON 双引号里的形式
std::string json_escape(const std::string& s);

// 解析 "bytes=start-end"，支持 "bytes=100-" 和 "bytes=-500" 两种省略写法。
// 返回 false 表示格式不认识，调用方应该退化成发完整文件。
bool parse_range(const std::string& range, uint64_t fileSize,
                 uint64_t& outStart, uint64_t& outEnd);

// ============ 组装 ============

// 只拼「状态行 + 头」，不拼 body。Content-Length 由调用方在 extra_headers 里自己给。
// 用于下载大文件：不能先把整个文件读进内存再拼，只能边读边发。
std::string build_head(int code, const std::string& status,
                       const std::string& content_type,
                       const std::string& extra_headers);

// 拼出完整响应，Content-Length 按 body 长度自动填
std::string build_response(int code, const std::string& status,
                           const std::string& content_type,
                           const std::string& body,
                           const std::string& extra_headers = "");
