#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <cstdint>
#include <cstddef>

// ==================== 存储层 ====================
//
// 设计要点（第6课）：
//
// 【传统做法】每个分片存成一个临时文件 chunk_0 / chunk_1 / ...，
//   全传完之后再读出来，按顺序拼成一个完整文件。
//   代价：每个字节被读一遍、写两遍。10GB 的文件就要多搬 10GB 的数据。
//
// 【本实现】上传开始时就把目标文件按最终大小"预分配"出来（稀疏文件），
//   每个分片到达后，直接用定位写（seek + write）砸进它最终该在的偏移位置。
//   全部到齐后，只需要一次 rename —— 也就是"零拷贝合并"。
//   每个字节只写一遍，没有第二次搬运。
//
// 这个优化能成立的前提是：分片是按固定大小切好的，第 i 片的偏移就是 i*chunkSize。
// 所以偏移量是算出来的，不需要任何额外记录。

struct FileInfo {
    std::string hash;
    std::string name;      // 原始文件名，只存元数据，从不参与拼路径
    uint64_t    size = 0;
};

// 一个上传会话（一次分片上传的进度记录）
struct UploadSession {
    std::string hash;
    std::string name;
    uint64_t    size = 0;
    uint64_t    chunkSize = 0;
    int         totalChunks = 0;

    std::string partPath;                 // storage/part/<hash>.part
    std::vector<char> received;           // received[i] != 0 表示第 i 片已到

    // 只保护 received 这个位图。
    // 千万别把磁盘写入也包进这把锁里 —— 那会让并发上传退化成串行。
    std::mutex mtx;
};

// 直接读文件的句柄。下载时用它流式读取，不需要把整个文件读进内存。
struct FileReader {
    int fd = -1;

    bool   open(const std::string& path);
    size_t read_at(uint64_t offset, char* buf, size_t len);
    void   close();
    ~FileReader() { close(); }
};

void store_init(const std::string& root);

// 文件是否已完整存在（用于"秒传"）
bool store_exists(const std::string& hash);

bool store_get(const std::string& hash, FileInfo& out);
std::vector<FileInfo> store_list();
bool store_remove(const std::string& hash);

// 打开或复用一个上传会话；receivedOut 填出"已收到的分片索引"（用于断点续传）。
// 返回 nullptr 表示 hash 不合法或预分配失败。
std::shared_ptr<UploadSession> store_open_session(const std::string& hash,
                                                  const std::string& name,
                                                  uint64_t size,
                                                  uint64_t chunkSize,
                                                  std::vector<int>& receivedOut);

std::shared_ptr<UploadSession> store_find_session(const std::string& hash);

// 把一片数据写到它在文件里的最终偏移位置
bool store_write_chunk(const std::shared_ptr<UploadSession>& s,
                       int index, const std::string& data);

int store_received_count(const std::shared_ptr<UploadSession>& s);

// 全部到齐后收尾：rename 成正式文件 + 写元数据
bool store_finish(const std::shared_ptr<UploadSession>& s);

// 正式文件的绝对/相对路径（下载用）
std::string store_file_path(const std::string& hash);

// hash 是否合法（纯十六进制 + 短横线）
bool store_hash_ok(const std::string& hash);
