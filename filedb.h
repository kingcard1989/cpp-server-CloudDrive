#pragma once
#include <libpq-fe.h>
#include <string>
#include <vector>

// ==================== 文件元数据的数据库层 ====================
//
// 这一层负责 files 表，也就是"谁拥有哪个文件"。
//
// 三层的分工说清楚：
//   store.cpp   只管磁盘上的字节，按 hash 存取，完全不知道有"用户"这回事
//   filedb.cpp  只管数据库里的归属和名字，不知道字节存在哪
//   两者靠 hash 对上
//
// 为什么名字和归属必须放数据库、不能放磁盘：
//   内容寻址下，alice 和 bob 传同一个文件时磁盘上只有一份 .dat。
//   但 alice 叫它 report.pdf、bob 叫它 报告.pdf —— 一份 blob 对多个名字。
//   磁盘上那个 .meta 只能写一个名字，这个模型它表达不了。

struct FileRow {
    std::string hash;
    std::string name;
    long long   size = 0;
};

// 记录"某用户拥有某文件"。已存在则什么都不做（幂等）。
bool filedb_add(PGconn* conn, long long ownerId, const std::string& hash,
                const std::string& name, long long size,
                int chunkSize, int chunkCount);

// 查某用户名下的单个文件。找到返回 true。
// ★ 下载和删除的鉴权全靠它 —— 查不到就说明"这个文件不是你的"。
bool filedb_get(PGconn* conn, long long ownerId, const std::string& hash, FileRow& out);

// 某用户的全部文件，按上传时间倒序。
bool filedb_list(PGconn* conn, long long ownerId, std::vector<FileRow>& out);

// 删掉某用户的这条记录。返回 true 表示确实删掉了一行。
// 注意：磁盘上的 blob 未必能删，还要用 filedb_refcount 判断。
bool filedb_remove(PGconn* conn, long long ownerId, const std::string& hash);

// 这个 hash 还被多少条记录引用着。返回 -1 表示查询失败。
long long filedb_refcount(PGconn* conn, const std::string& hash);
