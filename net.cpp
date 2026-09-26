#include "net.h"
#include "log.h"

bool init_network() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_line("[错误] WSAStartup 失败");
        return false;
    }
    log_line("[初始化] WinSock 2.2 已加载");
#endif
    return true;
}

void cleanup_network() {
#ifdef _WIN32
    WSACleanup();
#endif
}

socket_t create_listener(int port) {
    socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCK) {
        log_line("[错误] socket 创建失败，错误码: " + std::to_string(last_error()));
        return INVALID_SOCK;
    }

    // 允许重用地址：否则服务器重启时端口还处于 TIME_WAIT，bind 会失败
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<unsigned short>(port));
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
        log_line("[错误] bind 失败（端口被占用？），错误码: " + std::to_string(last_error()));
        CLOSE_SOCKET(fd);
        return INVALID_SOCK;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        log_line("[错误] listen 失败，错误码: " + std::to_string(last_error()));
        CLOSE_SOCKET(fd);
        return INVALID_SOCK;
    }

    log_line("[监听] 已绑定 0.0.0.0:" + std::to_string(port));
    return fd;
}

socket_t accept_one(socket_t listener, std::string& client_ip, int& client_port) {
    sockaddr_in client{};
    int client_len = sizeof(client);       // Windows 要 int*，Linux 要 socklen_t*

    socket_t conn = accept(listener, reinterpret_cast<sockaddr*>(&client), &client_len);
    if (conn == INVALID_SOCK) return INVALID_SOCK;

    client_ip   = inet_ntoa(client.sin_addr);
    client_port = ntohs(client.sin_port);
    return conn;
}

bool recv_headers(socket_t fd, std::string& raw) {
    // 64KB 栈上缓冲区。这里比原来的 4096 大得多，是第8课的一个优化点：
    // recv 是系统调用，每次要陷入内核。缓冲区越大，需要的调用次数越少。
    static thread_local char buf[64 * 1024];

    while (true) {
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return false;              // 0=对端关闭，<0=出错
        raw.append(buf, n);                    // 不能写 raw += buf，buf 里可能有 \0
        if (raw.find("\r\n\r\n") != std::string::npos) return true;
        if (raw.size() > 4 * 1024 * 1024) return false;   // 防御：请求头不该有这么大
    }
}

bool recv_until(socket_t fd, std::string& body, size_t need) {
    static thread_local char buf[64 * 1024];

    while (body.size() < need) {
        size_t remain = need - body.size();
        // 只要还差的那么多，不多要。多要的部分会被内核丢掉，白白浪费一次拷贝。
        int want = static_cast<int>(remain < sizeof(buf) ? remain : sizeof(buf));

        int n = recv(fd, buf, want, 0);
        if (n <= 0) return false;
        body.append(buf, n);
    }
    return true;
}

bool send_all(socket_t fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, data + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool send_all(socket_t fd, const std::string& data) {
    return send_all(fd, data.data(), data.size());
}
