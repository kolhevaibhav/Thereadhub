#pragma once

#include "pch.h"
#include "APIDBLib.h"

#include <cppconn/driver.h>
#include <boost/property_tree/ini_parser.hpp>

APIDBLib::~APIDBLib() {}

DBConnection::DBConnection(DbInfo DbInfo) {
    sql::Driver* driver = nullptr;
    inUse = false;
    try {
        driver = get_driver_instance();
        std::string dbServer = DbInfo.dbServer;
        std::string dbName = DbInfo.dbName;
        std::string userName = DbInfo.userName;
        std::string dbPassword = DbInfo.dbPassword;
        long port = DbInfo.port;

        std::string serverUrl = "tcp:

        connection = driver->connect(serverUrl, userName, dbPassword);
        connection->setSchema(dbName);
    }
    catch (sql::SQLException const &e) {
        std::cerr << "SQL Exception while creating connection: " << e.what() << std::endl;
    }
    catch (std::exception const &e) {
        std::cerr << "Standard Exception while creating connection: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown Exception while creating connection: " << std::endl;
    }
}

DBConnection::~DBConnection() {
    std::cout << "Dbconnection destructor called" << std::endl;
    delete connection;
}

sql::PreparedStatement* DBConnection::getQueryStatement(const std::string& sqlQuery) {
    sql::PreparedStatement* pstmt = connection->prepareStatement(sqlQuery);
    return pstmt;
}

void DBConnection::freeResultSet(sql::PreparedStatement* queryStatement, sql::ResultSet* result) {
    while (result->next()) {}
    while (queryStatement->getMoreResults()) {
        result =queryStatement->getResultSet();
        while (result->next()) {}
    }
}

bool DBConnection::isAvailable() {
    return !inUse;
}

void DBConnection::setInUse(bool val) {
    inUse = val;
}

int ConnectionPoolFactory::GetDatabaseConfig(DbInfo &DbInfo) {
    boost::property_tree::ptree pt;

    
    try {
        boost::property_tree::ini_parser::read_ini("config.ini", pt);
        
        DbInfo.dbServer = pt.get<std::string>("DBInfo.servername");
        DbInfo.dbName = pt.get<std::string>("DBInfo.databasename");
        DbInfo.userName = pt.get<std::string>("DBInfo.username");
        DbInfo.dbPassword = pt.get<std::string>("DBInfo.password");
        DbInfo.port = pt.get<int>("DBInfo.port");
    }
    catch (const boost::property_tree::ini_parser_error& e) {
        std::cerr << "Error while getting database config from INI file: " << e.message() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting database config from INI file: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "Unknown error while getting database config from INI file "<< std::endl;
        return 1;
    }
    return SUCCESS;
}

int ConnectionPoolFactory::GetConnectionPoolConfig(CpoolInfo &CpoolInfo) {
    boost::property_tree::ptree pt;

    
    try {
        boost::property_tree::ini_parser::read_ini("config.ini", pt);
        

        CpoolInfo.poolSize = pt.get<int>("poolingInfo.poolsize");
        CpoolInfo.checkTimer = pt.get<int>("poolingInfo.checkTimer");
        CpoolInfo.lotSize = pt.get<int>("poolingInfo.lotSize");
    }
    catch (const boost::property_tree::ini_parser_error& e) {
        std::cerr << "Error while getting connectionpool config from INI file: " << e.message() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting connectionpool config from INI file: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "Unknown error while getting connectionpool config from INI file " << std::endl;
        return 1;
    }
    return SUCCESS;
}

Cpool* ConnectionPoolFactory::CreateConnectionPool(DbInfo DbInfo, CpoolInfo CpoolInfo) {
    ConnectionPool* connectionPoolObj = nullptr;
    
    try {
        connectionPoolObj = new ConnectionPool(DbInfo, CpoolInfo.poolSize, CpoolInfo.lotSize);
        for (int i = 0; i < CpoolInfo.poolSize; i++) {
            
            connectionPoolObj->addConnection();
        }
        std::thread poolManager(manageConnectionPool, connectionPoolObj, CpoolInfo.checkTimer);
        poolManager.detach();
    }
    catch (std::exception const &e){
        std::cerr << "Error while creating connection pool: " << e.what() << std::endl;
        return nullptr;
    }
    catch (...) {
        std::cerr << "Unknown error while creating connection pool: "<< std::endl;
        return nullptr;
    }
    Cpool* cPoolObj = connectionPoolObj;
    return cPoolObj;
}

void ConnectionPoolFactory::manageConnectionPool(ConnectionPool* connectionPoolObj, int checkTimer) {
    while (true){
        std::this_thread::sleep_for(std::chrono::seconds(checkTimer));
        connectionPoolObj->removeExtraConnections();
        if (connectionPoolObj->getFreeConnectionCount()==0) {
            connectionPoolObj->addExtraConnectionsToCpool();
        }
    }
}

Cpool::~Cpool(){}

ConnectionPool::ConnectionPool(DbInfo dbInfo,int poolSize, int lotSize) {
    this->dbInfo = dbInfo;
    this->poolSize = poolSize;
    this->lotSize = lotSize;
    currentCount = 0;
    inUseCount = 0;
}

ConnectionPool::~ConnectionPool() {
    std::list<APIDBLib*>::iterator it;
    for (it = connList.begin(); it != connList.end(); ++it) {
        delete* it;
        *it = NULL;
    }
    connList.clear();
}

int ConnectionPool::getFreeConnectionCount() {
    return (currentCount - inUseCount);
}

void ConnectionPool::addConnection() {
    APIDBLib* conn = new DBConnection(this->dbInfo);
    connList.push_back(conn);
    currentCount++;
}

APIDBLib* ConnectionPool::getAvailableConnection() {
    APIDBLib* entry = nullptr;
    std::list<APIDBLib*>::iterator it;
    try {
        std::lock_guard <std::mutex> lock(cPoolMutex);
        for (it = connList.begin(); it != connList.end(); ++it) {
            entry = *it;
            DBConnection* conn = dynamic_cast<DBConnection*>(entry);
            if (conn->isAvailable()) {
                conn->setInUse(true);
                inUseCount++;
                return entry;
            }
        }
    }
    catch(std::exception const&e){
        std::cerr << "Error getting connection: " << e.what() << std::endl;
        return nullptr;
    }
    catch (...) {
        std::cerr << "Unknwon error while getting connection"<< std::endl;
        return nullptr;
    }
    this->addExtraConnectionsToCpool();
    return getAvailableConnection();
}

void ConnectionPool::addExtraConnectionsToCpool() {
    std::cout << "Adding extra connections" << std::endl;
    for (int i = 0; i < lotSize; i++) {
        this->addConnection();
    }
}

void ConnectionPool::releaseConnection(APIDBLib* connPtr) {
    std::lock_guard <std::mutex> lock(cPoolMutex);
    DBConnection* conn = dynamic_cast<DBConnection*>(connPtr);
    conn->setInUse(false);
    inUseCount--;
}

void ConnectionPool::removeExtraConnections() {
    std::cout << "Removing extra connections" << std::endl;
    APIDBLib* entry = nullptr;

    int extraFreeCount = 0;

    try {
        std::lock_guard <std::mutex> lock(cPoolMutex);
        if (inUseCount >= poolSize) {
            extraFreeCount = currentCount - inUseCount;
        }
        else {
            extraFreeCount = currentCount - poolSize;
        }

        int removableLot = extraFreeCount / lotSize;
        int removableConnections = removableLot * lotSize;

        int removedConnections = 0;
        std::list<APIDBLib*>::iterator it;

        if (removableConnections) {
            for (it = connList.begin(); it != connList.end(); ++it) {
                entry = *it;
                DBConnection* conn = dynamic_cast<DBConnection*>(entry);

                if (conn->isAvailable()) {
                    connList.erase(it);
                    delete conn;
                    conn = nullptr;
                    removedConnections++;
                    it--;
                    currentCount--;
                }
                if (removedConnections == removableConnections) {
                    break;
                }
            }
        }
    }
    catch (std::exception const& e) {
        std::cerr << "Error while removing extra connections: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown error while removing extra connections " << std::endl;
    }
}
