#include "User.h"
#include <boost/format.hpp>

std::unordered_map<int, Fault> User::faultCodes;
extern std::unique_ptr<Cpool> cpoolObj;

void process_get(http_request* request) {
    User user;
    try {
        if (request->absolute_uri().path().compare(U("/User/registration/init"))==0) {
            user.start = std::chrono::system_clock::now();
            auto queryParam = uri::split_query(request->request_uri().query());
            TXN_registrationInit txnRegistrationInit;
            int retCode = txnRegistrationInit.initializeRequestData(queryParam);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            APIDBLib* conn = cpoolObj->getAvailableConnection();
            retCode = txnRegistrationInit.checkIfUserIdAvailable(conn);
            cpoolObj->releaseConnection(conn);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            web::json::value result = web::json::value::null();
            retCode = txnRegistrationInit.getRegistrationTokenAsJson(result);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            user.replyOk(request, result.serialize());
        }
        else {
            user.faultCode = F_NOT_IMPLEMENTED;
            user.replyFault(request);
            return;
        }
    }
    catch (sql::SQLException& e) {
        std::cerr << "Sql Error occurred while processing request:" << e.what() << std::endl;
        user.faultCode = F_DATABASE_EXCEPTION;
        user.replyFault(request);
    }
    catch (std::exception& e) {
        std::cerr << "Std Error occurred while processing request:" << e.what() << std::endl;
        user.faultCode = F_SOMETHING_WENT_WRONG;
        user.replyFault(request);
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while processing request:" << std::endl;
        user.faultCode = F_SOMETHING_WENT_WRONG;
        user.replyFault(request);
    }
}
void process_post(http_request* request) {
    User user;
    try {
        if (request->absolute_uri().path().compare(U("/User/registration/details"))==0) {
            user.start = std::chrono::system_clock::now();
            const web::json::value requestData = request->extract_json().get();
            user.processHeader(request);

            TXN_PostRegDetails TxnPostRegDetails;
            int retCode = TxnPostRegDetails.initializeRequestData(requestData, user.headerData);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            retCode = TxnPostRegDetails.validateRequestData();
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            APIDBLib* conn = cpoolObj->getAvailableConnection();
            retCode = TxnPostRegDetails.checkIfEmailIsNotRegistered(conn);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            retCode = TxnPostRegDetails.insertUserRegistrationData(conn);
            cpoolObj->releaseConnection(conn);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            retCode = TxnPostRegDetails.sendRegistrationOTPToClient();
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            web::json::value result = TxnPostRegDetails.getResponseAsJson();
            user.replyOk(request, result.serialize());
        }
        else if (request->absolute_uri().path().compare(U("/User/registration/onetimetoken"))==0) {
            user.start = std::chrono::system_clock::now();
            user.processHeader(request);

            TXN_PostOTP TxnPostOTP;
            int retCode = TxnPostOTP.initializeRequestData(user.headerData);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            APIDBLib* conn = cpoolObj->getAvailableConnection();
            retCode = TxnPostOTP.validateRequestData(conn);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            retCode = TxnPostOTP.registerUser(conn);
            cpoolObj->releaseConnection(conn);
            if (retCode != SUCCESS) {
                user.faultCode = retCode;
                user.replyFault(request);
                return;
            }
            utility::string_t replyStr = U("Registration successful");
            user.replyOk(request, replyStr);
        }
        else {
            user.faultCode = F_NOT_IMPLEMENTED;
            user.replyFault(request);
            return;
            //not implemented
        }
    }
    catch (sql::SQLException& e) {
        std::cerr << "Sql Error occurred while processing request:" << e.what() << std::endl;
        user.faultCode = F_DATABASE_EXCEPTION;
        user.replyFault(request);
    }
    catch (std::exception& e) {
        std::cerr << "Std Error occurred while processing request:" << e.what() << std::endl;
        user.faultCode = F_SOMETHING_WENT_WRONG;
        user.replyFault(request);
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while processing request:" << std::endl;
        user.faultCode = F_SOMETHING_WENT_WRONG;
        user.replyFault(request);
    }
}
void process_put(http_request* request) {
    std::cout << "Processing request" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "request processed" << std::endl;
}
void process_delete(http_request* request) {
    std::cout << "Processing request" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "request processed" << std::endl;
}

void User::setFaultCodes() {
    APIBase::setFaultCodes();
    Fault faultResp;
    faultResp.code = F_INCORRECT_NO_OF_QUERY_PARAMS;
    faultResp.message = U(F_INCORRECT_NO_OF_QUERY_PARAMS_MESSAGE);
    faultResp.description = U(F_INCORRECT_NO_OF_QUERY_PARAMS_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INCORRECT_QUERY_PARAMS;
    faultResp.message = U(F_INCORRECT_QUERY_PARAMS_MESSAGE);
    faultResp.description = U(F_INCORRECT_QUERY_PARAMS_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_USERID;
    faultResp.message = U(F_INVALID_USERID_MESSAGE);
    faultResp.description = U(F_INVALID_USERID_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_EMAIL;
    faultResp.message = U(F_INVALID_EMAIL_MESSAGE);
    faultResp.description = U(F_INVALID_EMAIL_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_USERNAME;
    faultResp.message = U(F_INVALID_USERNAME_MESSAGE);
    faultResp.description = U(F_INVALID_USERNAME_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_PASSWORD;
    faultResp.message = U(F_INVALID_PASSWORD_MESSAGE);
    faultResp.description = U(F_INVALID_PASSWORD_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_BIRTHDATE;
    faultResp.message = U(F_INVALID_BIRTHDATE_MESSAGE);
    faultResp.description = U(F_INVALID_BIRTHDATE_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_USERID_TAKEN;
    faultResp.message = U(F_USERID_TAKEN_MESSAGE);
    faultResp.description = U(F_USERID_TAKEN_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::Conflict;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_REGISTRATION_TOKEN;
    faultResp.message = U(F_INVALID_REGISTRATION_TOKEN_MESSAGE);
    faultResp.description = U(F_INVALID_REGISTRATION_TOKEN_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::Unauthorized;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_ACCOUNT_ALREADY_EXISTS;
    faultResp.message = U(F_ACCOUNT_ALREADY_EXISTS_MESSAGE);
    faultResp.description = U(F_ACCOUNT_ALREADY_EXISTS_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::Conflict;

    User::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_INVALID_ONETIMETOKEN;
    faultResp.message = U(F_INVALID_ONETIMETOKEN_MESSAGE);
    faultResp.description = U(F_INVALID_ONETIMETOKEN_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::Unauthorized;

    User::faultCodes[faultResp.code] = faultResp;
}