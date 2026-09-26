#pragma once
#include <string>
#include <cstddef>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    
    using socket_t = SOCKET;
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <cerrno>
    using socket_t = int;
    #define CLOSE_SOCKET close
#endif

// 跨平台的"无效 socket"常量（Windows 是 0xFFFFFFFF，Linux 是 -1）
constexpr socket_t INVALID_SOCK = static_cast<socket_t>(-1);

// 跨平台取错误码
inline int last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool init_network();
void cleanup_network();

// socket + bind + listen 一步到位；失败返回 INVALID_SOCK
socket_t create_listener(int port);

// 阻塞等待一个客户端；成功返回连接 socket，并把对端地址写进 ip/port
socket_t accept_one(socket_t listener, std::string& client_ip, int& client_port);

// 循环 recv，直到读到请求头结束标记 \r\n\r\n
bool recv_headers(socket_t fd, std::string& raw);

// 继续收，直到 body 至少达到 need 字节。
// 注意 body 进来时可能已经有内容了（recv_headers 搭便车带回来的那一截）。
bool recv_until(socket_t fd, std::string& body, size_t need);

// 循环 send，直到全部发完。
// 带 (data,len) 的重载是为了发送大文件时不用先构造一个临时 std::string 拷贝。
bool send_all(socket_t fd, const char* data, size_t len);
bool send_all(socket_t fd, const std::string& data);
