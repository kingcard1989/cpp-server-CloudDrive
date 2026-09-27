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
//
// ==================== 第 5 步：磁盘不再存业务元数据 ====================
//
// 多用户之后，blob 是内容寻址的：alice 和 bob 传同一个文件，磁盘上只有一份。
// 但"这个文件叫什么名字、属于谁"是每人各一份的。
//
// 一份 blob 对多个名字 —— 磁盘上的 .meta 根本表达不了这个模型，
// 所以名字和归属全部搬进数据库的 files 表。
//
// 磁盘从此只负责一件事：按 hash 存字节。
// 原来的 FileInfo / store_get / store_list 就此退役。

// 一个上传会话（一次分片上传的进度记录）
struct UploadSession {
    std::string hash;
    std::string name;
    uint64_t    size = 0;
    uint64_t    chunkSize = 0;
    int         totalChunks = 0;
    long long   ownerId = 0;              // 这个上传会话属于谁

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

bool store_remove(const std::string& hash);

// 打开或复用一个上传会话；receivedOut 填出"已收到的分片索引"（用于断点续传）。
//
// 会话按 (ownerId, hash) 共同标识，不是只按 hash ——
// 两个人同时上传同一个文件时，他们各自有独立的会话和 .part 文件，
// 不会互相看到对方的进度，也不会争抢同一个预分配文件。
//
// 返回 nullptr 表示 hash 不合法或预分配失败。
std::shared_ptr<UploadSession> store_open_session(const std::string& hash,
                                                  const std::string& name,
                                                  uint64_t size,
                                                  uint64_t chunkSize,
                                                  long long ownerId,
                                                  std::vector<int>& receivedOut);

std::shared_ptr<UploadSession> store_find_session(long long ownerId,
                                                  const std::string& hash);

// 把一片数据写到它在文件里的最终偏移位置
bool store_write_chunk(const std::shared_ptr<UploadSession>& s,
                       int index, const std::string& data);

int store_received_count(const std::shared_ptr<UploadSession>& s);

// 全部到齐后收尾：rename 成正式文件
bool store_finish(const std::shared_ptr<UploadSession>& s);

// 正式文件的路径（下载用）
std::string store_file_path(const std::string& hash);

// hash 是否合法（纯十六进制 + 短横线）
bool store_hash_ok(const std::string& hash);

// 把客户端送来的文件名洗一遍（去掉换行、只取最后一段路径、截断长度）。
//
// 上传和秒传两条路径都必须过这一道：
// 秒传不建会话，名字不会经过 store_open_session，漏掉就会把原始名字
// 直接写进数据库，最后原样出现在 Content-Disposition 响应头里 ——
// 名字里塞个 \r\n 就是一次 HTTP 响应头注入。
std::string store_clean_name(const std::string& raw);
