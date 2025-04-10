#pragma once

#include "Transactions.h"
#include <memory>

class User :public APIBase {
public:
	static std::unordered_map<int, Fault> faultCodes;
	virtual std::unordered_map<int, Fault> getFaultCodes() {
		return User::faultCodes;
	}
	static void setFaultCodes();
};

void process_get(http_request* request);
void process_post(http_request* request);
void process_put(http_request* request);
void process_delete(http_request* request);
