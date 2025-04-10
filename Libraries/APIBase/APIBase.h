#pragma once

#ifdef APIBASE_EXPORTS 
#define BASE_API __declspec(dllexport)
#else  
#define BASE_API __declspec(dllimport)
#endif

#include "APIErrorCodes.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/asio/thread_pool.hpp>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <thread>
#include <iostream>
#include <string>
#include <unordered_map>
#include <cstring>
#include <sstream>
#include <iomanip>

#define SUCCESS		0
#define KEY			"0421376589abfdec0153426987abcfed"
#define IV			"thereadhub123456"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace utility;

BASE_API std::istream* base64Decode(const utility::string_t& base64_image);
BASE_API std::string encrypt(const std::string& plaintext);
BASE_API std::string decrypt(const std::string& ciphtxt);

struct BASE_API Header {
	utility::string_t sessionToken = U("");
	utility::string_t oneTimeToken = U("");
	utility::string_t registrationToken = U("");
	utility::string_t userId = U("");
	utility::string_t ip = U("");
	utility::string_t xForwardedFor = U("");
};

struct BASE_API Fault{
	int code = 0;
	int httpStatusCode = 0;
	utility::string_t message = U("");
	utility::string_t description = U("");
	utility::string_t exceptionStr = U("");
	bool exceptionFlag = false;

	web::json::value AsJson() const{
		web::json::value faultData = web::json::value::object();
		faultData[U("code")] = web::json::value::number(code);
		faultData[U("message")] = web::json::value::string(message);
		faultData[U("description")] = web::json::value::string(description);

		web::json::value result = web::json::value::object();
		result[U("fault")] = faultData;

		return result;
	}
};

class BASE_API APIListener {
	http_listener listener;
	boost::asio::thread_pool pool;

	void(*funcGet)(http_request*);
	void(*funcPost)(http_request*);
	void(*funcPut)(http_request*);
	void(*funcDelete)(http_request*);

public:
	APIListener(utility::string_t url, int threadCount,void(*funcGet)(http_request*), void(*funcPost)(http_request*), void(*funcPut)(http_request*), void(*funcDelete)(http_request*));

	~APIListener();

	void handleGet(http_request request);
	void handlePost(http_request request);
	void handlePut(http_request request);
	void handleDelete(http_request request);

	static std::unique_ptr<APIListener> initialize(void(*processGet)(http_request*), void(*processPost)(http_request*), void(*processPut)(http_request*), void(*processDelete)(http_request*));

	pplx::task<void>open() {
		return listener.open();
	}
	pplx::task<void>close() {
		return listener.close();
	}
};

class BASE_API APIBase {
	static std::unordered_map<int, Fault> faultCodes;
public:
	int faultCode = 0;
	Header headerData;
	std::chrono::system_clock::time_point start;
	std::chrono::system_clock::time_point end;

	static void setFaultCodes();
	virtual std::unordered_map<int, Fault> getFaultCodes() {
		return APIBase::faultCodes;
	}
	void processHeader(http_request* request);
	void replyFault(http_request* request, utility::string_t userId = U(""));
	void replyOk(http_request* request, utility::string_t replyStr, utility::string_t userId=U(""));
};