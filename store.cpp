#include "store.h"
#include "log.h"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cstdlib>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace fs = std::filesystem;

static std::string g_root;      // 例如 "storage"
static std::string g_dataDir;   // storage/data  —— 完成的文件
static std::string g_partDir;   // storage/part  —— 上传中的文件

// 保护下面这张会话表。注意它保护的只是"表的增删查"，
// 具体某个会话的位图由它自己的 mtx 保护。
static std::mutex g_mtx;
static std::map<std::string, std::shared_ptr<UploadSession>> g_sessions;

// 会话的键。用 (ownerId, hash) 而不是只有 hash ——
// 两个人同时上传同一个文件时 hash 完全相同，只按 hash 存会撞在一起。
static std::string session_key(long long ownerId, const std::string& hash) {
    return std::to_string(ownerId) + ":" + hash;
}

// ==================== 路径与小工具 ====================

static std::string data_path(const std::string& hash) { return g_dataDir + "/" + hash + ".dat"; }
static std::string meta_path(const std::string& hash) { return g_dataDir + "/" + hash + ".meta"; }
// 分片临时文件同样按 (ownerId, hash) 分开。
// 两个人同时传同一个文件时 hash 相同，共用一个 .part 会互相踩：
// 先完成的那位把 .part rename 走了，后一位的写入就打到空气上了。
static std::string part_path(long long ownerId, const std::string& hash) {
    return g_partDir + "/" + std::to_string(ownerId) + "_" + hash + ".part";
}

bool store_hash_ok(const std::string& h) {
    if (h.size() < 8 || h.size() > 64) return false;
    for (char c : h) {
        bool ok = (c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F') ||
                  c == '-';
        if (!ok) return false;
    }
    return true;
}

// 把客户端送来的文件名洗一遍：
// 1. 干掉换行（会破坏 .meta 的行结构）
// 2. 只取最后一段路径，挡掉 "../../windows/win.ini" 这种
//
// ★ 安全要点：绝对不要拿用户给的文件名去拼磁盘路径。
//   本实现里磁盘上的文件名一律是 hash，原始名字只写在 .meta 里当数据用，
//   所以就算这里漏了，也影响不到路径。这叫"纵深防御"。
std::string store_clean_name(const std::string& raw) {
    std::string n;
    for (char c : raw) {
        if (c == '\r' || c == '\n') continue;
        n.push_back(c);
    }
    size_t p = n.find_last_of("/\\");
    if (p != std::string::npos) n = n.substr(p + 1);
    if (n.empty()) n = "unnamed";
    if (n.size() > 200) n.resize(200);
    return n;
}

// ==================== 底层文件操作 ====================

// 把文件一次性撑到 size 大小。
// Windows 的 _chsize_s / POSIX 的 ftruncate 都会把新扩出来的区域填成 0，
// 所以文件从创建那一刻起就是"完整大小、内容是洞"的状态。
static bool preallocate(const std::string& path, uint64_t size) {
#ifdef _WIN32
    int fd = _open(path.c_str(), _O_RDWR | _O_CREAT | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return false;
    bool ok = (_chsize_s(fd, static_cast<long long>(size)) == 0);
    _close(fd);
    return ok;
#else
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) return false;
    bool ok = (ftruncate(fd, static_cast<off_t>(size)) == 0);
    ::close(fd);
    return ok;
#endif
}

// 把 data 写到文件的 offset 偏移处。
//
// ★ 并发关键点：每次调用独立 open / close 一个文件句柄。
//   文件句柄自带读写位置，所以两个线程各写各的偏移，互相完全不干扰，
//   不需要任何锁。这里的锁成本是 0 —— 这是本设计最重要的性能来源。
//   （如果所有线程共用一个句柄，就必须在 seek+write 外面套一把大锁，
//     并发上传会直接退化成串行。）
static bool write_at(const std::string& path, uint64_t offset, const std::string& data) {
#ifdef _WIN32
    int fd = _open(path.c_str(), _O_WRONLY | _O_BINARY);
    if (fd < 0) return false;

    bool ok = false;
    if (_lseeki64(fd, static_cast<long long>(offset), SEEK_SET) >= 0) {
        unsigned int total = 0;
        while (total < data.size()) {
            int n = _write(fd, data.data() + total,
                           static_cast<unsigned int>(data.size() - total));
            if (n <= 0) break;
            total += static_cast<unsigned int>(n);
        }
        ok = (total == data.size());
    }
    _close(fd);
    return ok;
#else
    int fd = ::open(path.c_str(), O_WRONLY);
    if (fd < 0) return false;

    size_t total = 0;
    while (total < data.size()) {
        // pwrite = "带偏移的 write"，不改变文件句柄自己的位置，天生适合并发写
        ssize_t n = pwrite(fd, data.data() + total, data.size() - total,
                           static_cast<off_t>(offset + total));
        if (n <= 0) break;
        total += static_cast<size_t>(n);
    }
    ::close(fd);
    return total == data.size();
#endif
}

// ==================== FileReader ====================

bool FileReader::open(const std::string& path) {
    close();
#ifdef _WIN32
    fd = _open(path.c_str(), _O_RDONLY | _O_BINARY);
#else
    fd = ::open(path.c_str(), O_RDONLY);
#endif
    return fd >= 0;
}

size_t FileReader::read_at(uint64_t offset, char* buf, size_t len) {
    if (fd < 0) return 0;
#ifdef _WIN32
    if (_lseeki64(fd, static_cast<long long>(offset), SEEK_SET) < 0) return 0;
    int n = _read(fd, buf, static_cast<unsigned int>(len));
#else
    ssize_t n = pread(fd, buf, len, static_cast<off_t>(offset));
#endif
    return n > 0 ? static_cast<size_t>(n) : 0;
}

void FileReader::close() {
    if (fd < 0) return;
#ifdef _WIN32
    _close(fd);
#else
    ::close(fd);
#endif
    fd = -1;
}

// ==================== 对外接口 ====================

void store_init(const std::string& root) {
    g_root    = root;
    g_dataDir = root + "/data";
    g_partDir = root + "/part";

    std::error_code ec;
    fs::create_directories(g_dataDir, ec);
    fs::create_directories(g_partDir, ec);

    log_line("[存储] 数据目录: " + fs::absolute(g_dataDir).string());
}

bool store_exists(const std::string& hash) {
    if (!store_hash_ok(hash)) return false;
    std::error_code ec;
    return fs::exists(data_path(hash), ec);
}

std::string store_file_path(const std::string& hash) {
    return data_path(hash);
}

bool store_remove(const std::string& hash) {
    if (!store_hash_ok(hash)) return false;

    std::error_code ec;
    bool any = false;
    any |= fs::remove(data_path(hash), ec);
    any |= fs::remove(meta_path(hash), ec);   // 清掉第 5 步之前遗留的 .meta

    {   // 残留的上传会话也一起清掉。
        //   会话按 "ownerId:hash" 存，所以要把属于这个 hash 的全部扫出来。
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto it = g_sessions.begin(); it != g_sessions.end(); ) {
            if (it->second->hash == hash) it = g_sessions.erase(it);
            else ++it;
        }
    }

    // 分片临时文件是 "<ownerId>_<hash>.part"，同样按后缀扫
    std::string suffix = "_" + hash + ".part";
    if (fs::exists(g_partDir, ec)) {
        for (const auto& e : fs::directory_iterator(g_partDir, ec)) {
            std::string n = e.path().filename().string();
            if (n.size() > suffix.size() &&
                n.compare(n.size() - suffix.size(), suffix.size(), suffix) == 0) {
                fs::remove(e.path(), ec);
            }
        }
    }

    return any;
}

std::shared_ptr<UploadSession> store_open_session(const std::string& hash,
                                                  const std::string& name,
                                                  uint64_t size,
                                                  uint64_t chunkSize,
                                                  long long ownerId,
                                                  std::vector<int>& receivedOut) {
    receivedOut.clear();
    if (!store_hash_ok(hash)) return nullptr;
    if (chunkSize == 0) return nullptr;

    const std::string key = session_key(ownerId, hash);

    std::lock_guard<std::mutex> lk(g_mtx);

    // 已有会话 → 直接复用，把进度原样报回去（这就是断点续传）
    auto it = g_sessions.find(key);
    if (it != g_sessions.end()) {
        auto s = it->second;
        std::lock_guard<std::mutex> slk(s->mtx);
        for (int i = 0; i < s->totalChunks; ++i) {
            if (s->received[i]) receivedOut.push_back(i);
        }
        return s;
    }

    auto s = std::make_shared<UploadSession>();
    s->hash        = hash;
    s->name        = store_clean_name(name);
    s->size        = size;
    s->chunkSize   = chunkSize;
    s->totalChunks = static_cast<int>(size == 0 ? 1 : (size + chunkSize - 1) / chunkSize);
    s->ownerId     = ownerId;
    s->received.assign(static_cast<size_t>(s->totalChunks), 0);
    s->partPath    = part_path(ownerId, hash);

    // 预分配：文件一创建就是最终大小，后面的分片直接往对应偏移砸。
    // 这一步是"零拷贝合并"的前提。
    std::error_code ec;
    if (!fs::exists(s->partPath, ec)) {
        if (!preallocate(s->partPath, size)) {
            log_line("[存储] 预分配失败: " + s->partPath);
            return nullptr;
        }
    }

    g_sessions[key] = s;
    return s;
}

std::shared_ptr<UploadSession> store_find_session(long long ownerId,
                                                  const std::string& hash) {
    std::lock_guard<std::mutex> lk(g_mtx);
    auto it = g_sessions.find(session_key(ownerId, hash));
    return (it == g_sessions.end()) ? nullptr : it->second;
}

bool store_write_chunk(const std::shared_ptr<UploadSession>& s,
                       int index, const std::string& data) {
    if (!s) return false;
    if (index < 0 || index >= s->totalChunks) return false;

    uint64_t offset = static_cast<uint64_t>(index) * s->chunkSize;

    // 期望这一片有多长：最后一片可能不满，空文件则是 0
    uint64_t expect = s->chunkSize;
    if (s->size <= offset) {
        expect = 0;
    } else if (s->size - offset < s->chunkSize) {
        expect = s->size - offset;
    }

    // 长度必须精确匹配。不校验的话，客户端发一个超长 body 就能把文件写花。
    if (data.size() != expect) return false;

    // ↓↓↓ 注意：写磁盘这一步不持任何锁 ↓↓↓
    // 每个分片写的是不同偏移、用的是独立句柄，天然并发安全。
    if (!write_at(s->partPath, offset, data)) return false;

    // 锁只保护内存里这一个字节的位图更新
    std::lock_guard<std::mutex> slk(s->mtx);
    s->received[index] = 1;
    return true;
}

int store_received_count(const std::shared_ptr<UploadSession>& s) {
    if (!s) return 0;
    std::lock_guard<std::mutex> slk(s->mtx);
    int n = 0;
    for (char c : s->received) if (c) ++n;
    return n;
}

bool store_finish(const std::shared_ptr<UploadSession>& s) {
    if (!s) return false;

    // 先确认一片不缺
    {
        std::lock_guard<std::mutex> slk(s->mtx);
        for (int i = 0; i < s->totalChunks; ++i) {
            if (!s->received[i]) return false;
        }
    }

    std::error_code ec;
    if (fs::exists(data_path(s->hash), ec)) {
        // 这个 hash 的文件已经在最终位置上了 —— 说明有别人（或更早的一次上传）
        // 传过一模一样的内容。内容寻址下同一个 hash 就是同一份字节，
        // 磁盘上那份就是我们要的，把自己的 .part 丢掉即可。
        //
        // ★ 这正是"一份 blob 对多个名字"的现场：
        //   alice 叫它 report.pdf、bob 叫它 报告.pdf，磁盘上只有这一个 .dat。
        //   所以名字绝不能存在磁盘上，只能存数据库 —— 一个字段装不下两个名字。
        fs::remove(s->partPath, ec);
    } else {
        // ★ 这里就是"合并"——其实没有合并。
        //   因为每一片从一开始就落在了最终位置上，收尾只是一次改名的原子操作。
        //   如果是"先存 N 个临时文件再拼接"的老做法，这里要完整读写一遍磁盘。
        fs::rename(s->partPath, data_path(s->hash), ec);
        if (ec) {
            log_line("[存储] rename 失败: " + ec.message());
            return false;
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_sessions.erase(s->hash);
    }

    log_line("[存储] 上传完成 " + s->name + "  (" + std::to_string(s->size) + " 字节)");
    return true;
}
