#include "db.h"
#include "log.h"
using namespace std;
PGconn* db_connect(const string& conninfo){
    PGconn* conn  = PQconnectdb(conninfo.c_str());
    if(PQstatus(conn)!=CONNECTION_OK){
    log_line(string("[db] 连接失败: ") + PQerrorMessage(conn));
    PQfinish(conn);
    return nullptr;
    }
    log_line("successdbconn");
    return conn;

}
void db_close(PGconn* conn){
if(conn) PQfinish(conn);
}