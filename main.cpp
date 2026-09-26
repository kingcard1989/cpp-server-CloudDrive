#include "net.h"
#include "http.h"
#include "store.h"
#include "log.h"
#include "auth.h"
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <algorithm>

constexpr int         port      = 9000;
constexpr const char* WWW_ROOT  = "www";

// 单次请求 body 上限。分片最大也就几 MB，这里给足余量。
// 不加这个限制，客户端只要发一句 "Content-Length: 99999999999"，
// 服务器就会老老实实往内存里收，直到内存耗尽。
constexpr size_t MAX_BODY = 16 * 1024 * 1024;

// 下载时每块读多大。越大系统调用越少，但内存占用越高。256KB 是个舒服的折中。
constexpr size_t SEND_BLOCK = 256 * 1024;

static std::atomic<int> g_seq{0};

// ==================== 小工具 ====================

static const char* status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 413: return "Payload Too Large";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

static void send_text(socket_t conn, int code, const std::string& text) {
    send_all(conn, build_response(code, status_text(code),
                                  "text/plain; charset=utf-8", text));
}

static void send_json(socket_t conn, const std::string& json, int code = 200) {
    send_all(conn, build_response(code, status_text(code),
                                  "application/json; charset=utf-8", json));
}

static std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::string mime_of(const std::string& path) {
    auto ends = [&](const char* suf) {
        size_t n = std::strlen(suf);
        return path.size() >= n && path.compare(path.size() - n, n, suf) == 0;
    };
    if (ends(".html")) return "text/html; charset=utf-8";
    if (ends(".css"))  return "text/css; charset=utf-8";
    if (ends(".js"))   return "application/javascript; charset=utf-8";
    if (ends(".json")) return "application/json; charset=utf-8";
    if (ends(".svg"))  return "image/svg+xml";
    if (ends(".png"))  return "image/png";
    if (ends(".jpg"))  return "image/jpeg";
    if (ends(".ico"))  return "image/x-icon";
    return "application/octet-stream";
}

// ★ 安全要点：静态文件请求里的路径是客户端说了算的。
// 不检查的话，请求 "/static/../../../../windows/win.ini" 就能读到系统文件。
// 这里一刀切掉所有带 ".."、冒号、或反斜杠开头的路径。
static bool safe_static_path(const std::string& p) {
    if (p.empty()) return false;
    if (p.find("..") != std::string::npos) return false;
    if (p.find('\\') != std::string::npos) return false;
    if (p.find(':')  != std::string::npos) return false;
    if (p[0] == '/') return false;
    return true;
}

// ==================== 下载（含 Range 支持）====================

static void handle_download(socket_t conn, const HttpRequest& req, const std::string& hash) {
    FileInfo fi;
    if (!store_get(hash, fi)) {
        send_text(conn, 404, "找不到这个文件\n");
        return;
    }

    uint64_t start = 0;
    uint64_t end   = (fi.size > 0) ? fi.size - 1 : 0;
    int         code = 200;
    std::string extra;

    // 客户端可以带 Range 头只请求文件的一段。
    // 下载器靠这个续传，播放器靠这个拖动进度条。
    std::string range = header_of(req, "range");
    if (!range.empty() && parse_range(range, fi.size, start, end)) {
        code = 206;
        extra += "Content-Range: bytes " + std::to_string(start) + "-" +
                 std::to_string(end) + "/" + std::to_string(fi.size) + "\r\n";
    } else {
        start = 0;
        end   = (fi.size > 0) ? fi.size - 1 : 0;
    }

    uint64_t total = (fi.size == 0) ? 0 : (end - start + 1);

    extra += "Accept-Ranges: bytes\r\n";
    extra += "Content-Length: " + std::to_string(total) + "\r\n";
    // 文件名在上传时已经被 sanitize 过（不含 \r\n），所以没法用它做响应头注入。
    // json_escape 负责把引号转义掉，免得文件名里的 " 把这一行提前结束。
    extra += "Content-Disposition: attachment; filename=\"" + json_escape(fi.name) + "\"\r\n";

    // 先只发头。注意这里用的是 build_head 而不是 build_response ——
    // 因为文件可能很大，不能先整个读进内存再发。
    if (!send_all(conn, build_head(code, status_text(code), "application/octet-stream", extra))) {
        return;
    }
    if (total == 0) return;

    // 再流式发 body：读一块、发一块。
    // 内存占用恒定为 SEND_BLOCK，跟文件大小无关 —— 10GB 的文件也只用 256KB。
    FileReader reader;
    if (!reader.open(store_file_path(hash))) return;

    std::string blk;
    blk.resize(SEND_BLOCK);

    uint64_t pos    = start;
    uint64_t remain = total;

    while (remain > 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(SEND_BLOCK, remain));
        size_t got  = reader.read_at(pos, &blk[0], want);
        if (got == 0) break;
        // 用 (指针,长度) 版发送，避免为了发一块就构造一个临时 std::string
        if (!send_all(conn, blk.data(), got)) break;
        pos    += got;
        remain -= got;
    }
}

// ==================== API ====================

static std::string qs(const std::map<std::string, std::string>& q, const char* key) {
    auto it = q.find(key);
    return (it == q.end()) ? std::string() : it->second;
}

static void api_list(socket_t conn) {
    auto files = store_list();
    std::string j = "{\"ok\":true,\"files\":[";
    for (size_t i = 0; i < files.size(); ++i) {
        if (i) j += ",";
        j += "{\"hash\":\"" + files[i].hash + "\",";
        j += "\"name\":\"" + json_escape(files[i].name) + "\",";
        j += "\"size\":" + std::to_string(files[i].size) + "}";
    }
    j += "]}";
    send_json(conn, j);
}

static void api_upload_init(socket_t conn, const std::map<std::string, std::string>& q) {
    std::string hash      = qs(q, "hash");
    std::string name      = qs(q, "name");
    uint64_t    size      = std::strtoull(qs(q, "size").c_str(), nullptr, 10);
    uint64_t    chunkSize = std::strtoull(qs(q, "chunkSize").c_str(), nullptr, 10);

    if (!store_hash_ok(hash) || chunkSize == 0 || name.empty()) {
        send_json(conn, "{\"ok\":false,\"error\":\"参数不合法\"}", 400);
        return;
    }

    // ---------- 秒传 ----------
    // 这个哈希的文件服务器上已经有了，一个字节都不用传。
    // 前提是客户端算哈希的方式和服务器对文件内容的认知一致。
    if (store_exists(hash)) {
        log_line("[秒传] " + name);
        send_json(conn, "{\"ok\":true,\"status\":\"instant\"}");
        return;
    }

    std::vector<int> received;
    auto s = store_open_session(hash, name, size, chunkSize, received);
    if (!s) {
        send_json(conn, "{\"ok\":false,\"error\":\"无法创建上传会话\"}", 500);
        return;
    }

    // ---------- 断点续传 ----------
    // 把"已经收到哪些分片"报给客户端，客户端只补缺的那些。
    std::string list;
    for (size_t i = 0; i < received.size(); ++i) {
        if (i) list += ",";
        list += std::to_string(received[i]);
    }

    std::string st = received.empty() ? "new" : "resume";
    log_line("[上传] " + name +
             "  总分片=" + std::to_string(s->totalChunks) +
             "  已有=" + std::to_string(received.size()) +
             "  (" + (st == "new" ? "新任务" : "续传") + ")");

    send_json(conn, "{\"ok\":true,\"status\":\"" + st + "\","
                    "\"uploadId\":\"" + hash + "\","
                    "\"totalChunks\":" + std::to_string(s->totalChunks) + ","
                    "\"received\":[" + list + "]}");
}

static void api_upload_chunk(socket_t conn, const std::map<std::string, std::string>& q,
                             const std::string& body) {
    std::string uploadId = qs(q, "uploadId");
    std::string idxStr   = qs(q, "index");
    if (uploadId.empty() || idxStr.empty()) {
        send_json(conn, "{\"ok\":false,\"error\":\"缺少 uploadId 或 index\"}", 400);
        return;
    }

    int  index = std::atoi(idxStr.c_str());
    auto s     = store_find_session(uploadId);
    if (!s) {
        send_json(conn, "{\"ok\":false,\"error\":\"上传会话不存在\"}", 404);
        return;
    }

    if (!store_write_chunk(s, index, body)) {
        send_json(conn, "{\"ok\":false,\"error\":\"分片长度不对或写入失败\"}", 400);
        return;
    }

    // 打印分片编号，你会看到它们不是 0,1,2,3 顺序到达的 ——
    // 这正是并发上传在起作用的证据。
    log_line("  " + std::to_string(index) + " 号分片到达  " +
             std::to_string(body.size()) + " 字节");

    send_json(conn, "{\"ok\":true,\"index\":" + std::to_string(index) + "}");
}

static void api_upload_complete(socket_t conn, const std::map<std::string, std::string>& q) {
    std::string uploadId = qs(q, "uploadId");
    auto s = store_find_session(uploadId);
    if (!s) {
        send_json(conn, "{\"ok\":false,\"error\":\"上传会话不存在\"}", 404);
        return;
    }
    if (!store_finish(s)) {
        send_json(conn, "{\"ok\":false,\"error\":\"还有分片没到齐\"}", 400);
        return;
    }
    send_json(conn, "{\"ok\":true}");
}

static void api_delete(socket_t conn, const std::map<std::string, std::string>& q) {
    std::string hash = qs(q, "hash");
    if (hash.empty() || !store_remove(hash)) {
        send_json(conn, "{\"ok\":false,\"error\":\"删除失败\"}", 404);
        return;
    }
    log_line("[删除] " + hash);
    send_json(conn, "{\"ok\":true}");
}

// ==================== 路由 ====================

static void route(socket_t conn, int seq, const HttpRequest& req, const std::string& body) {
    const std::string& p = req.path;
    auto q = parse_query(req.query);

    // 分片请求不发日志（太密），所以这条日志单独处理
    bool isChunk = (p == "/api/upload/chunk");
    if (!isChunk) {
        log_line("[" + std::to_string(seq) + "] " + req.method + " " + p +
                 (body.empty() ? "" : "  body=" + std::to_string(body.size())));
    }

    // ---- 首页 ----
    if (p == "/" || p == "/index.html") {
        std::string html = read_file(std::string(WWW_ROOT) + "/index.html");
        if (html.empty()) {
            send_text(conn, 500, "读不到 www/index.html，请确认是在 cpp 目录下运行\n");
            return;
        }
        send_all(conn, build_response(200, "OK", "text/html; charset=utf-8", html));
        return;
    }

    // ---- 静态资源 ----
    if (p.rfind("/static/", 0) == 0) {
        std::string rel = p.substr(8);
        if (!safe_static_path(rel)) {
            log_line("[拦截] 非法静态路径: " + rel);
            send_text(conn, 403, "非法路径\n");
            return;
        }
        std::string full = std::string(WWW_ROOT) + "/" + rel;
        std::string data = read_file(full);
        if (data.empty()) {
            send_text(conn, 404, "静态文件不存在\n");
            return;
        }
        send_all(conn, build_response(200, "OK", mime_of(full), data));
        return;
    }

    // ---- 文件列表 ----
    if (p == "/api/list") {
        api_list(conn);
        return;
    }

    // ---- 上传三件套 ----
    if (p == "/api/upload/init")     { api_upload_init(conn, q); return; }
    if (p == "/api/upload/chunk")    { api_upload_chunk(conn, q, body); return; }
    if (p == "/api/upload/complete") { api_upload_complete(conn, q); return; }

    // ---- 删除 ----
    if (p == "/api/delete") { api_delete(conn, q); return; }

    // ---- 下载 ----
    if (p.rfind("/download/", 0) == 0) {
        handle_download(conn, req, p.substr(10));
        return;
    }

    send_text(conn, 404, "404: " + p + "\n");
}

// ==================== 单连接处理 ====================

static void handle_client(socket_t conn, const std::string& ip, int seq) {
    std::string raw;
    if (!recv_headers(conn, raw)) {
        CLOSE_SOCKET(conn);
        return;
    }

    HttpRequest req;
    if (!parse_request_line(raw, req)) {
        send_text(conn, 400, "请求行解析失败\n");
        CLOSE_SOCKET(conn);
        return;
    }
    parse_headers(raw, req);
 if (!auth_ok(header_of(req, "authorization"))) {
        send_all(conn, build_response(401, status_text(401),
                                      "text/plain; charset=utf-8",
                                      "需要登录\n",
                                      auth_challenge()));
        CLOSE_SOCKET(conn);
        return;
    }
    // 有些客户端（curl、部分下载器）在发大 body 之前会先发一句
    // "Expect: 100-continue" 探路，等服务器回 "100 Continue" 才肯把 body 吐出来。
    // 不回它的话，客户端会干等约 1 秒然后硬发 —— 功能正常，但每个请求白等一秒。
    // 浏览器 fetch 不发这个头，所以只在用 curl 之类工具测的时候才看得到差别。
    if (header_of(req, "expect").find("100-continue") != std::string::npos) {
        send_all(conn, "HTTP/1.1 100 Continue\r\n\r\n");
    }

    // ★ 把搭便车跟过来的那截 body 取出来。丢掉它的话，
    //   POST 上来的分片开头会变成一堆 0 字节，文件末尾还会对不上。
    std::string body = body_so_far(raw);

    size_t need = static_cast<size_t>(header_num(req, "content-length"));
    if (need > MAX_BODY) {
        send_text(conn, 413, "请求体过大\n");
        CLOSE_SOCKET(conn);
        return;
    }

    if (body.size() < need) {
        if (!recv_until(conn, body, need)) {
            CLOSE_SOCKET(conn);
            return;
        }
    }
    // 多收的字节属于下一个请求（keep-alive 场景），这里用不上，截掉
    body.resize(need);
    req.body = body;

    route(conn, seq, req, body);

    CLOSE_SOCKET(conn);
}

// ==================== 入口 ====================

int main() {
    if (!init_network()) return 1;
    init_console_utf8();
    store_init("storage");
    auth_init(".env");
    log_line("[启动] 网盘服务器 v0.9 —— 分片上传 / 断点续传 / 秒传 / Range 下载");

    socket_t listener = create_listener(port);
    if (listener == INVALID_SOCK) {
        cleanup_network();
        return 1;
    }

    log_line("[就绪] 浏览器打开 http://127.0.0.1:" + std::to_string(port));

    while (true) {
        std::string ip;
        int p = 0;
        socket_t conn = accept_one(listener, ip, p);
        if (conn == INVALID_SOCK) continue;

        int seq = ++g_seq;

        // ★ 第8课的核心改动：一个连接一个线程。
        //
        //   改之前：浏览器同时发 3 个分片，服务器只能一个一个处理，
        //           "并发上传"其实是假的。
        //   改之后：3 个分片是真的在同时收、同时往磁盘的不同偏移写。
        //
        //   注意 accept 循环本身必须立刻回到 accept 上。
        //   任何耗时操作放在这里，整个服务器就退化成串行了。
        //
        //   detach() = 主线程不等这个线程，它自己管自己。
        //   代价是程序退出时不会等它们收尾 —— 对常驻服务器来说可以接受。
        std::thread(handle_client, conn, ip, seq).detach();
    }

    CLOSE_SOCKET(listener);
    cleanup_network();
    return 0;
}
