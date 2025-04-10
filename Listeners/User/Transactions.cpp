#include "Transactions.h"
#include "defines.h"
#include <regex>
#include <curl/curl.h>

bool userIdIsValid(const utility::string_t userId) {
    if (userId.empty()) {
        return false;
    }
    if (userId.length() < 5 || userId.length() > 8) {
        return false;
    }
    for (auto& ch : userId) {
        if (!std::isalnum(ch, std::locale())) {
            return false;
        }
    }
    return true;
}
bool emailIdIsValid(const utility::string_t emailId) {
    const std::regex pattern(
        R"((^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$))"
    );
    std::string email = utility::conversions::to_utf8string(emailId);
    return std::regex_match(email, pattern);
}
bool passwordIsValid(const utility::string_t password) {
    if (password.empty()) {
        return false;
    }
    else if (password.length() < 8 || password.length()>15) {
        return false;
    }
    std::string passwordStr = utility::conversions::to_utf8string(password);
    std::regex upper_case_regex("[A-Z]");
    std::regex lower_case_regex("[a-z]");
    std::regex digit_regex("[0-9]");
    std::regex special_char_regex("[!@#$*-]");

    bool has_upper = std::regex_search(passwordStr, upper_case_regex);
    bool has_lower = std::regex_search(passwordStr, lower_case_regex);
    bool has_digit = std::regex_search(passwordStr, digit_regex);
    bool has_special = std::regex_search(passwordStr, special_char_regex);

    return has_upper && has_lower && has_digit && has_special;
}
bool birthDateIsValid(const utility::string_t &bDate) {
    std::string birthDate = utility::conversions::to_utf8string(bDate);
    std::tm tmObj = {};
    std::istringstream iss(birthDate);
    iss >> std::get_time(&tmObj, "%m-%d-%Y");
    if (iss.fail()) {
        return false;
    }
    int year = tmObj.tm_year + 1900; 
    int month = tmObj.tm_mon + 1;    
    int day = tmObj.tm_mday;

    
    bool validYear = (year >= 1900 && year <= 9999);
    bool validMonth = (month >= 1 && month <= 12);
    bool validDay = (day >= 1 && day <= 31);

    
    std::time_t currentTime = std::time(nullptr); 
    std::tm currentTm;
    localtime_s(&currentTm,&currentTime); 
    std::time_t parsedTime = std::mktime(&tmObj);
    std::time_t currentTimeMidnight = std::mktime(&currentTm);

    bool dateIsLessThanCurrent = (parsedTime < currentTimeMidnight);

    return validYear && validMonth && validDay && dateIsLessThanCurrent;
}
std::string getRandomOTT() {
    const int min = 0;
    const int max = 9;

    std::random_device rd;
    std::mt19937 gen(rd());
    
    std::uniform_int_distribution<> dis(min, max);

    std::string otp;
    for (int i = 0; i < 6; ++i) {
        otp += std::to_string(dis(gen));
    }
    return otp;
}

size_t Email::payload_source(void* ptr, size_t size, size_t nmemb, void* userp) {
    const char** payload = reinterpret_cast<const char**>(userp);
    if (size * nmemb < 1) {
        return 0;
    }
    if (*payload) {
        size_t len = strlen(*payload);
        memcpy(ptr, *payload, len);
        *payload += len;
        return len;
    }
    return 0;
}
int Email::sendEmail(){
    try {
        const std::string payload_text =
            "To: " + recipientMail + "\r\n"
            "From: Thereadhub <myemail@gmail.com>\r\n"
            "Subject: " + subject + "\r\n"
            "\r\n"
            "" + mailBody + "\r\n";
        CURL* curl;
        CURLcode res = CURLE_OK;

        const char* smtpServer = "smtp:
        const char* smtpUsername = "myemail@gmail.com";
        const char* smtpPassword = "myemailpassword";
        const char* fromEmail = "myemail@gmail.com";
        const char* toEmail = recipientMail.c_str();

        curl = curl_easy_init();
        if (curl) {
            struct curl_slist* recipients = NULL;

            curl_easy_setopt(curl, CURLOPT_URL, smtpServer);
            curl_easy_setopt(curl, CURLOPT_USERNAME, smtpUsername);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, smtpPassword);
            curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
            curl_easy_setopt(curl, CURLOPT_MAIL_FROM, fromEmail);
            recipients = curl_slist_append(recipients, toEmail);
            curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
            const char* payload = payload_text.c_str();
            curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
            curl_easy_setopt(curl, CURLOPT_READDATA, &payload);
            curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                return F_SOMETHING_WENT_WRONG;
            }
            curl_slist_free_all(recipients);
            curl_easy_cleanup(curl);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while sending email: " << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    return SUCCESS;
}

int TXN_registrationInit::initializeRequestData(const std::map<utility::string_t, utility::string_t>queryParam) {
    if (queryParam.size() != 1) {
        return F_INCORRECT_NO_OF_QUERY_PARAMS;
    }
    else if (queryParam.find(U("userId")) == queryParam.end()) {
        return F_BAD_REQUEST;
    }
    else {
        utility::string_t lvUserId = queryParam.at(U("userId"));
        if (!userIdIsValid(lvUserId)) {
            return F_INVALID_USERID;
        }
        userId = lvUserId;
        return SUCCESS;
    }
}
int TXN_registrationInit::checkIfUserIdAvailable(APIDBLib* conn) {
    try {
        queryStatement = conn->getQueryStatement("CALL prc_check_userid_availability (?)");
        queryStatement->setString(1, utility::conversions::to_utf8string(userId));
        result = queryStatement->executeQuery();
        if (result->next()) {
            bool userIdAvailable = result->getBoolean("isAvailable");
            conn->freeResultSet(queryStatement, result);
            if (!userIdAvailable) {
                return F_USERID_TAKEN;
            }
        }
        else {
            return F_DATABASE_EXCEPTION;
        }
    }
    catch (const sql::SQLException& e) {
        std::cerr << "Sql Error occurred while processing userIdAvailability transaction:" << e.what() << std::endl;
        return F_DATABASE_EXCEPTION;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while processing userIdAvailability transaction:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while processing userIdAvailability transaction" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    return SUCCESS;
}
int TXN_registrationInit::getRegistrationTokenAsJson(web::json::value &result) {
    std::string registrationToken = encrypt(utility::conversions::to_utf8string(userId));
    if (registrationToken == "") {
        return F_SOMETHING_WENT_WRONG;
    }
    
    result[U("registrationToken")] = web::json::value::string(utility::conversions::to_string_t(registrationToken));
    std::cout << "Preparing result successful" << std::endl;
    return SUCCESS;
}
TXN_registrationInit::~TXN_registrationInit() {
    delete queryStatement;
    delete result;
}

int TXN_PostRegDetails::initializeRequestData(const web::json::value& requestData,const Header &headerData) {
    try {
        this->userName = requestData.at(U("username")).as_string();
        this->userId = requestData.at(U("userId")).as_string();
        this->emailId = requestData.at(U("emailId")).as_string();
        this->password = requestData.at(U("password")).as_string();
        this->birthDate = requestData.at(U("birthDate")).as_string();
        this->about = requestData.at(U("about")).as_string();
        utility::string_t base64_image = requestData.at(U("profilePic")).as_string();
        this->profilePic = base64Decode(base64_image);
        this->registrationToken = headerData.registrationToken;
        return SUCCESS;
    }
    catch (const web::json::json_exception& e) {
        std::cerr << "JSON exception  : " << e.what() << std::endl;
        return F_BAD_REQUEST;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while initalizing post registration details transaction:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Error occurred while initalizing post registration details transaction:" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
}
int TXN_PostRegDetails::validateRequestData() {
    if (userName.empty()) {
        return F_INVALID_USERNAME;
    }
    if (!userIdIsValid(userId)) {
        return F_INVALID_USERID;
    }
    std::string decryptedToken = decrypt(utility::conversions::to_utf8string(registrationToken));
    if ((decryptedToken == "") || decryptedToken != utility::conversions::to_utf8string(userId)) {
        return F_INVALID_REGISTRATION_TOKEN;
    }
    if (!emailIdIsValid(emailId)) {
        return F_INVALID_EMAIL;
    }
    if (!passwordIsValid(password)) {
        return F_INVALID_PASSWORD;
    }
    if (!birthDateIsValid(birthDate)) {
        return F_INVALID_BIRTHDATE;
    }
    return SUCCESS;
}
int TXN_PostRegDetails::checkIfEmailIsNotRegistered(APIDBLib* conn) {
    try {
        queryStatement = conn->getQueryStatement("CALL prc_check_emailid_availability (?)");
        queryStatement->setString(1, utility::conversions::to_utf8string(emailId));
        result = queryStatement->executeQuery();
        if (result->next()) {
            bool alreadyRegistered = result->getBoolean("alreadyRegistered");
            conn->freeResultSet(queryStatement, result);
            if (alreadyRegistered) {
                return F_ACCOUNT_ALREADY_EXISTS;
            }
            return SUCCESS;
        }
        else {
            return F_DATABASE_EXCEPTION;
        }
    }
    catch (const sql::SQLException& e) {
        std::cerr << "Sql Error occurred while processing emailIdAvailability transaction:" << e.what() << std::endl;
        return F_DATABASE_EXCEPTION;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while processing emailIdAvailability transaction:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while processing emailIdAvailability transaction" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
}
int TXN_PostRegDetails::insertUserRegistrationData(APIDBLib* conn) {
    std::string OTT = getRandomOTT();
    oneTimeToken = utility::conversions::to_string_t(OTT);
    std::string encryptedOTT = encrypt(OTT);
    try {
        queryStatement = conn->getQueryStatement("CALL prc_post_user_registration_details (?,?,?,?,?,?,?,?)");
        queryStatement->setString(1, utility::conversions::to_utf8string(userId));
        queryStatement->setString(2, utility::conversions::to_utf8string(userName));
        queryStatement->setString(3, utility::conversions::to_utf8string(password));
        queryStatement->setString(4, utility::conversions::to_utf8string(emailId));
        queryStatement->setString(5, utility::conversions::to_utf8string(birthDate));
        queryStatement->setString(6, utility::conversions::to_utf8string(about));
        queryStatement->setBlob(7, profilePic);
        queryStatement->setString(8, utility::conversions::to_utf8string(encryptedOTT));
        queryStatement->executeUpdate();
    }
    catch (const sql::SQLException& e) {
        std::cerr << "Sql Error occurred while processing post registration details transaction:" << e.what() << std::endl;
        return F_DATABASE_EXCEPTION;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while processing post registration details transaction:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while processing post registration details transaction" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    return SUCCESS;
}
int TXN_PostRegDetails::sendRegistrationOTPToClient() {
    Email emailObj;
    emailObj.recipientMail = utility::conversions::to_utf8string(emailId);
    emailObj.subject = D_EMAIL_SUBJECT_OTP_FOR_REGISTRATION;
    emailObj.mailBody = D_EMAIL_BODY_OTP_FOR_REGISTRATION(oneTimeToken);
    int retCode = emailObj.sendEmail();
    return retCode;
}
web::json::value TXN_PostRegDetails::getResponseAsJson() {
    web::json::value result;
    utility::string_t message = U(D_MSG_SUCCESS_POST_REGDETAILS);
    result[U("message")] = web::json::value::string(message);
    return result;
}
TXN_PostRegDetails::~TXN_PostRegDetails() {
    delete queryStatement;
    delete profilePic;
    delete result;
}

int TXN_PostOTP::initializeRequestData(const Header& headerData) {
    try {
        this->userId = headerData.userId;
        this->oneTimeToken = headerData.oneTimeToken;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while initalizing post OTP transaction:" << e.what() << std::endl;
        return F_BAD_REQUEST;
    }
    return SUCCESS;
}
int TXN_PostOTP::validateRequestData(APIDBLib* conn) {
    if (!userIdIsValid(userId)) {
        return F_INVALID_USERID;
    }
    std::string encryptedOTT = encrypt(utility::conversions::to_utf8string(oneTimeToken));
    try {
        queryStatement = conn->getQueryStatement("CALL prc_get_onetimetoken (?)");
        queryStatement->setString(1, utility::conversions::to_utf8string(userId));
        result = queryStatement->executeQuery();
        if (result->next()) {
            std::string OTTFromDatabase = result->getString("OneTimeToken");
            conn->freeResultSet(queryStatement, result);
            if (OTTFromDatabase != encryptedOTT) {
                return F_INVALID_ONETIMETOKEN;
            }
        }
        else {
            return F_DATABASE_EXCEPTION;
        }
    }
    catch (const sql::SQLException& e) {
        std::cerr << "Sql Error occurred while validating onetimetoken:" << e.what() << std::endl;
        return F_DATABASE_EXCEPTION;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while validating onetimetoken:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while validating onetimetoken" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    return SUCCESS;
}
int TXN_PostOTP::registerUser(APIDBLib* conn) {
    try {
        queryStatement = conn->getQueryStatement("CALL prc_register_user (?)");
        queryStatement->setString(1, utility::conversions::to_utf8string(userId));
        queryStatement->executeUpdate();
    }
    catch (const sql::SQLException& e) {
        std::cerr << "Sql Error occurred while registerting user:" << e.what() << std::endl;
        return F_DATABASE_EXCEPTION;
    }
    catch (const std::exception& e) {
        std::cerr << "Std Error occurred while registerting user:" << e.what() << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    catch (...) {
        std::cerr << "Unknown Error occurred while registerting user" << std::endl;
        return F_SOMETHING_WENT_WRONG;
    }
    return SUCCESS;
}

TXN_PostOTP::~TXN_PostOTP() {
    delete queryStatement;
    delete result;
}
