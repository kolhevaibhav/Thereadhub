#pragma once

#include "APIBase.h"
#include "APIDBLib.h"
#include "ErrorCodes.h"
#include <ctime>
#include <random>

#include <cppconn/exception.h>

static bool userIdIsValid(const utility::string_t userId);
static bool emailIdIsValid(const utility::string_t emailId);
static bool passwordIsValid(const utility::string_t emailId);
static bool birthDateIsValid(const utility::string_t& bDate);
static std::string getRandomOTP();

struct Email {
	std::string recipientMail = { "" };
	std::string subject = { "" };
	std::string mailBody = { "" };

	int sendEmail();
private:
	static size_t payload_source(void* ptr, size_t size, size_t nmemb, void* userp);
};

struct TXN_registrationInit {
	utility::string_t userId = U("");
	int initializeRequestData(const std::map<utility::string_t, utility::string_t>queryParam);
	~TXN_registrationInit();
	int checkIfUserIdAvailable(APIDBLib* conn);
	int getRegistrationTokenAsJson(web::json::value& result);
private:
	sql::PreparedStatement* queryStatement = nullptr;
	sql::ResultSet* result = nullptr;
};

struct TXN_PostRegDetails {
	std::istream* profilePic = nullptr;
	utility::string_t userName = U("");
	utility::string_t userId = U("");
	utility::string_t emailId = U("");
	utility::string_t password = U("");
	utility::string_t birthDate = U("");
	utility::string_t about = U("");
	utility::string_t registrationToken = U("");
	utility::string_t oneTimeToken = U("");

	~TXN_PostRegDetails();
	int initializeRequestData(const web::json::value& requestData, const Header& headerData);
	int validateRequestData();
	int checkIfEmailIsNotRegistered(APIDBLib* conn);
	int insertUserRegistrationData(APIDBLib* conn);
	int sendRegistrationOTPToClient();
	web::json::value getResponseAsJson();
private:
	sql::PreparedStatement* queryStatement = nullptr;
	sql::ResultSet* result = nullptr;
};

struct TXN_PostOTP {
	utility::string_t userId = U("");
	utility::string_t oneTimeToken = U("");
	utility::string_t sessionToken = U("");

	~TXN_PostOTP();
	int initializeRequestData(const Header& headerData);
	int validateRequestData(APIDBLib* conn);
	int registerUser(APIDBLib* conn);
private:
	sql::PreparedStatement* queryStatement = nullptr;
	sql::ResultSet* result = nullptr;
};