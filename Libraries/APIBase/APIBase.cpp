#pragma once

#include "pch.h"
#include "APIBase.h"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/asio/post.hpp>
#include <boost/exception/all.hpp>

#include <cpprest/uri.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace boost::archive::iterators;

std::unordered_map<int, Fault> APIBase::faultCodes;

APIListener::APIListener(utility::string_t url, int threadCount, void(*funcGet)(http_request*), void(*funcPost)(http_request*), void(*funcPut)(http_request*), void(*funcDelete)(http_request*)) : listener(url),pool(threadCount)
{
    this->funcGet = funcGet;
    this->funcPost = funcPost;
    this->funcPut = funcPut;
    this->funcDelete = funcDelete;

    listener.support(methods::GET, std::bind(&APIListener::handleGet, this, std::placeholders::_1));
    listener.support(methods::POST, std::bind(&APIListener::handlePost, this, std::placeholders::_1));
    listener.support(methods::PUT, std::bind(&APIListener::handlePut, this, std::placeholders::_1));
    listener.support(methods::DEL, std::bind(&APIListener::handleDelete, this, std::placeholders::_1));
}

APIListener::~APIListener() {}

std::unique_ptr<APIListener> APIListener::initialize(void(*processGet)(http_request*), void(*processPost)(http_request*), void(*processPut)(http_request*), void(*processDelete)(http_request*)) {

    boost::property_tree::ptree pt;
    std::unique_ptr<APIListener> g_http;
    try {
        boost::property_tree::ini_parser::read_ini("config.ini", pt);

        std::string module = pt.get<std::string>("ListenerInfo.modulename");
        std::string host = pt.get<std::string>("ListenerInfo.host");
        std::string port = pt.get<std::string>("ListenerInfo.port");
        utility::string_t address = utility::conversions::to_string_t(host + port);

        uri_builder uri(address);
        uri.append_path(utility::conversions::to_string_t(module));

        auto addr = uri.to_uri().to_string();

        g_http = std::unique_ptr<APIListener>(new APIListener(addr, (int)std::thread::hardware_concurrency(), processGet, processPost, processPut, processDelete));

        g_http->open().wait();
        std::cout << "Listening for requests at: " << utility::conversions::to_utf8string(addr) << std::endl;
    }
    catch (const boost::property_tree::ini_parser_error& e) {
        std::cerr << "Error reading INI file while initializing listener: " << e.message() << std::endl;
        return nullptr;
    }
    catch (std::exception const &e) {
        std::cerr << "Error initializing listener: " << e.what() << std::endl;
        return nullptr;
    }
    catch (...) {
        std::cerr << "Error initializing listener" <<std::endl;
        return nullptr;
    }

    return std::move(g_http);
}

void APIListener::handleGet(http_request req) {

    
    http_request* request = new http_request(req);
    try {
        boost::asio::post(pool, [this, request]() mutable {
            funcGet(request);
            });
    }
    catch (std::exception const& e) {
        std::cerr << "Error handling GET request: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "General exception in handling GET request " << std::endl;
    }
}

void APIListener::handlePost(http_request req) {
    http_request* request = new http_request(req);
    try {
        boost::asio::post(pool, [this, request]() mutable {
            funcPost(request);
            });
    }
    catch (std::exception const& e) {
        std::cerr << "Error handling POST request: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "General exception in handling POST request " << std::endl;
    }
}

void APIListener::handlePut(http_request req) {
    http_request* request = new http_request(req);
    try {
        boost::asio::post(pool, [this, request]() mutable {
            funcPut(request);
            });
    }
    catch (std::exception const& e) {
        std::cerr << "Error handling PUT request: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "General exception in handling PUT request " << std::endl;
    }
}

void APIListener::handleDelete(http_request req) {
    http_request* request = new http_request(req);
    try {
        boost::asio::post(pool, [this, request]() mutable {
            funcDelete(request);
            });
    }
    catch (std::exception const& e) {
        std::cerr << "Error handling DELETE request: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "General exception in handling DELETE request " << std::endl;
    }
}

void APIBase::processHeader(http_request* request) {
    std::cout << "Request: " << utility::conversions::to_utf8string(request->method().c_str()) << " : " << utility::conversions::to_utf8string(uri::decode(request->absolute_uri().path()).c_str()) << std::endl;
    for (auto itr = request->headers().begin(); itr != request->headers().end(); itr++) {

        if (itr->first.compare(U("sessionToken"))==0) {
            headerData.sessionToken = itr->second;
            std::cout << "Process header - SessionToken : "<< utility::conversions::to_utf8string(headerData.sessionToken) << std::endl;
        }
        else if (itr->first.compare(U("userId"))==0) {
            headerData.userId = itr->second;
            std::cout << "Process header - userId : " << utility::conversions::to_utf8string(headerData.userId) << std::endl;
        }
        else if (itr->first.compare(U("ip"))==0) {
            headerData.ip = itr->second;
            std::cout << "Process header - ip : " << utility::conversions::to_utf8string(headerData.ip) << std::endl;
        }
        else if (itr->first.compare(U("xForwardedFor"))==0) {
            headerData.xForwardedFor = itr->second;
            std::cout << "Process header - xForwardedFor : " << utility::conversions::to_utf8string(headerData.xForwardedFor) << std::endl;
        }
        else if (itr->first.compare(U("oneTimeToken"))==0) {
            headerData.oneTimeToken = itr->second;
            std::cout << "Process header - oneTimeToken : " << utility::conversions::to_utf8string(headerData.oneTimeToken) << std::endl;
        }
        else if (itr->first.compare(U("registrationToken"))==0) {
            headerData.registrationToken = itr->second;
            std::cout << "Process header - registrationToken : " << utility::conversions::to_utf8string(headerData.registrationToken) << std::endl;
        }
    }
}

void APIBase::replyOk(http_request* request, utility::string_t replyStr, utility::string_t userId) {
    web::json::value successData = web::json::value::object();
    successData[U("Success")] = web::json::value::string(replyStr);
    http_response response;
    end = std::chrono::system_clock::now();
    auto response_time = (std::chrono::duration_cast<std::chrono::milliseconds>)(end - start);
    std::cout << "Processed in: "<<response_time.count() << std::endl;

    response.headers().set_content_type(L"application/json");
    response.headers().add(L"Timestamp", response_time.count());

    response.set_status_code(status_codes::OK);
    response.set_body(successData.serialize().c_str());
    request->reply(response);
    
    if (request) {
        delete request;
        request = nullptr;
    }
}

void APIBase::replyFault(http_request* request, utility::string_t userId) {
    Fault faultResp;
    int code = this->faultCode;
    std::cout <<"Fault code: "<<code <<std::endl;
    try {
        std::unordered_map<int, Fault> faultCodeMap = this->getFaultCodes();

        auto itr = faultCodeMap.find(code);
        if (itr != faultCodeMap.end()) {
            faultResp = itr->second;
        }
        else{
            itr = APIBase::faultCodes.find(code);
            if (itr != APIBase::faultCodes.end()) {
                faultResp = itr->second;
            }
            else {
                std::cout << "Fault code not found on server, please check code passed" << std::endl;
                faultResp.code = F_SOMETHING_WENT_WRONG;
                faultResp.message = U(F_SOMETHING_WENT_WRONG_MESSAGE);
                faultResp.description = U(F_SOMETHING_WENT_WRONG_DESCRIPTION);
                faultResp.httpStatusCode = status_codes::InternalError;
            }
        }
    }
    catch (const http_exception& e) {
        std::cerr << "Http exception occured while sending response: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard exception occured while sending response: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception occured while sending response" << std::endl;
    }

    web::json::value faultRespJson = faultResp.AsJson();

    http_response response;
    end = std::chrono::system_clock::now();
    auto response_time = (std::chrono::duration_cast<std::chrono::milliseconds>)(end - start);
    std::cout << "Processed in: " << response_time.count() << std::endl;
    response.headers().set_content_type(L"application/json");
    response.headers().add(L"Timestamp", response_time.count());

    response.set_status_code(web::http::status_code(faultResp.httpStatusCode));
    response.set_body(faultRespJson.serialize().c_str());
    request->reply(response);

    if (request) {
        delete request;
        request = nullptr;
    }
}

void APIBase::setFaultCodes() {
    Fault faultResp;
    faultResp.code = F_SOMETHING_WENT_WRONG;
    faultResp.message = U(F_SOMETHING_WENT_WRONG_MESSAGE);
    faultResp.description = U(F_SOMETHING_WENT_WRONG_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::InternalError;

    APIBase::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_DATABASE_EXCEPTION;
    faultResp.message = U(F_DATABASE_EXCEPTION_MESSAGE);
    faultResp.description = U(F_DATABASE_EXCEPTION_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::FailedDependency;

    APIBase::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_BAD_REQUEST;
    faultResp.message = U(F_BAD_REQUEST_MESSAGE);
    faultResp.description = U(F_BAD_REQUEST_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::BadRequest;

    APIBase::faultCodes[faultResp.code] = faultResp;

    faultResp.code = F_NOT_IMPLEMENTED;
    faultResp.message = U(F_NOT_IMPLEMENTED_MESSAGE);
    faultResp.description = U(F_NOT_IMPLEMENTED_DESCRIPTION);
    faultResp.httpStatusCode = status_codes::NotImplemented;

    APIBase::faultCodes[faultResp.code] = faultResp;
}

std::istream* base64Decode(const utility::string_t& base64_image) {
    try {
        utility::string_t encoded = base64_image;

        
        auto pos = base64_image.find(U("base64,"));
        if (pos != std::string::npos) {
            encoded = base64_image.substr(pos + 7);
        }
        std::string stdEncoded = utility::conversions::to_utf8string(encoded);
        using base64_dec = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

        std::vector<uint8_t> decoded(base64_dec(stdEncoded.begin()), base64_dec(stdEncoded.end()));

        std::string data_str(decoded.begin(), decoded.end());
        std::istringstream* img_obj = new std::istringstream(data_str);
        return img_obj;
    }
    catch (boost::exception const& e) {
        std::cerr << "Boost exception occurred while decoding image data: " << boost::diagnostic_information(e) << std::endl;
        return nullptr;
    }
    catch (std::exception& e) {
        std::cerr << "Standard Exception occurred while decoding image data: " << e.what() << std::endl;
    }
}

std::string encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    std::string ciphertext;

    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Error: EVP_CIPHER_CTX_new() failed" << std::endl;
        return "";
    }

    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)KEY, (const unsigned char*)IV) != 1) {
        std::cerr << "Error: EVP_EncryptInit_ex() failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    
    int plaintext_len = plaintext.length();
    int ciphertext_len = 0;
    unsigned char* encrypted = new unsigned char[plaintext_len + AES_BLOCK_SIZE];

    if (EVP_EncryptUpdate(ctx, encrypted, &len, (const unsigned char*)plaintext.c_str(), plaintext_len) != 1) {
        std::cerr << "Error: EVP_EncryptUpdate() failed" << std::endl;
        delete[] encrypted;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    
    if (EVP_EncryptFinal_ex(ctx, encrypted + ciphertext_len, &len) != 1) {
        std::cerr << "Error: EVP_EncryptFinal_ex() failed" << std::endl;
        delete[] encrypted;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    
    ciphertext.assign((char*)encrypted, ciphertext_len);

    
    delete[] encrypted;
    EVP_CIPHER_CTX_free(ctx);

    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        hexStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(ciphertext[i]));
    }
    return hexStream.str();
}

std::string decrypt(const std::string& ciphtxt) {
    std::string ciphertext;
    for (size_t i = 0; i < ciphtxt.length(); i += 2) {
        std::string byteString = ciphtxt.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        ciphertext += byte;
    }
    EVP_CIPHER_CTX* ctx;
    int len;
    std::string plaintext;

    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Error: EVP_CIPHER_CTX_new() failed" << std::endl;
        return "";
    }

    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char*)KEY, (const unsigned char*)IV) != 1) {
        std::cerr << "Error: EVP_DecryptInit_ex() failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    
    int ciphertext_len = ciphertext.length();
    int plaintext_len = 0;
    unsigned char* decrypted = new unsigned char[ciphertext_len + AES_BLOCK_SIZE];

    if (EVP_DecryptUpdate(ctx, decrypted, &len, (const unsigned char*)ciphertext.c_str(), ciphertext_len) != 1) {
        std::cerr << "Error: EVP_DecryptUpdate() failed" << std::endl;
        delete[] decrypted;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    
    if (EVP_DecryptFinal_ex(ctx, decrypted + plaintext_len, &len) != 1) {
        std::cerr << "Error: EVP_DecryptFinal_ex() failed" << std::endl;
        delete[] decrypted;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    
    plaintext.assign((char*)decrypted, plaintext_len);

    
    delete[] decrypted;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}