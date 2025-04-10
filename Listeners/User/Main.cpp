#include "User.h"

std::unique_ptr<Cpool> cpoolObj;

int main() {
    User::setFaultCodes();

    DbInfo dbInfo;
    CpoolInfo cpoolInfo;
    int retCode = ConnectionPoolFactory::GetDatabaseConfig(dbInfo);
    if (retCode != SUCCESS) {
        return 0;
    }
    int retCode = ConnectionPoolFactory::GetConnectionPoolConfig(cpoolInfo);
    if (retCode != SUCCESS) {
        return 0;
    }
    cpoolObj = std::unique_ptr<Cpool>(ConnectionPoolFactory::CreateConnectionPool(dbInfo, cpoolInfo));
    if (!cpoolObj) {
        return 0;
    }

    std::unique_ptr<APIListener> g_http = APIListener::initialize(process_get, process_post, process_put, process_delete);
    if (!g_http) {
        return 0;
    }
    std::cout << "Press enter to exit: " << std::endl;

    std::string line;
    std::getline(std::cin, line);

    g_http->close().wait();

    return 0;
}