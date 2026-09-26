#pragma once
#include <string>
#include <iostream>
#include <mutex>
#include <cstdio>

#ifdef _WIN32
#  include <windows.h>
#endif

// 在 main() 里调一次
inline void init_console_utf8() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    // Linux/macOS 本身就是 UTF-8，无需处理
}

inline void log_line(const std::string& msg) {
    static std::mutex mtx;
    std::lock_guard<std::mutex> lk(mtx);
    std::cout << msg << '\n';
}