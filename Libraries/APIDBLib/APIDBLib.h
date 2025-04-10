#pragma once

#include <iostream>
#include <mutex>
#include <cppconn/prepared_statement.h>
#include <boost/property_tree/ptree.hpp>

#define SUCCESS 0


#ifdef APIDBLIB_EXPORTS 
#define DBLIB_API __declspec(dllexport)
#else  
#define DBLIB_API __declspec(dllimport)
#endif


struct DBLIB_API DbInfo {
	std::string dbServer = { "" };
	std::string dbName = { "" };
	std::string userName = { "" };
	std::string dbPassword = { "" };
	long port = 0;
};

struct DBLIB_API CpoolInfo {
	int poolSize = 0;
	int lotSize = 0;
	int checkTimer = 0;
};

class DBLIB_API APIDBLib {
	
public:
	virtual void freeResultSet(sql::PreparedStatement* queryStatement, sql::ResultSet* result) = 0;
	virtual sql::PreparedStatement* getQueryStatement(const std::string& sqlQuery) = 0;
	virtual ~APIDBLib() = 0;
};

class DBConnection : public APIDBLib  {
private:
	sql::Connection* connection = nullptr;
	bool inUse = false;
public:
	DBConnection(DbInfo DbInfo);
	~DBConnection();
	sql::PreparedStatement* getQueryStatement(const std::string& sqlQuery);
	void freeResultSet(sql::PreparedStatement* queryStatement, sql::ResultSet* result);
	bool isAvailable();
	void setInUse(bool val);
};

class DBLIB_API Cpool {
public:
	virtual APIDBLib* getAvailableConnection() = 0;
	virtual void releaseConnection(APIDBLib* conn) = 0;
	virtual ~Cpool() = 0;
};

class ConnectionPool : public Cpool {
private:
	std::list< APIDBLib*>connList;
	std::mutex cPoolMutex;
	DbInfo dbInfo;
	int currentCount;
	int inUseCount;
	int poolSize;
	int lotSize;

public:
	ConnectionPool(DbInfo dbInfo, int poolSize,int lotSize);
	~ConnectionPool();
	void addConnection();
	APIDBLib* getAvailableConnection();
	void addExtraConnectionsToCpool();
	void releaseConnection(APIDBLib* conn);
	void removeExtraConnections();
	int getFreeConnectionCount();
};

class DBLIB_API ConnectionPoolFactory {
public:
	static Cpool* CreateConnectionPool(DbInfo DbInfo, CpoolInfo CpoolInfo);
	static int GetConnectionPoolConfig(CpoolInfo& CpoolInfo);
	static int GetDatabaseConfig(DbInfo& DbInfo);
	static void manageConnectionPool(ConnectionPool* connectionPoolObj, int checkTimer);
};