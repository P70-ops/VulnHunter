#include "../include/http_utils.h"
#include <curl/curl.h>
#include <sstream>
#include <stdexcept>

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static size_t header_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    std::vector<std::string>* headers = (std::vector<std::string>*)userp;
    std::string header((char*)contents, size * nmemb);
    if (!header.empty() && header.back() == '\n') header.pop_back();
    if (!header.empty() && header.back() == '\r') header.pop_back();
    if (!header.empty()) headers->push_back(header);
    return size * nmemb;
}

HTTPResponse fetch_http_response(const std::string& host, int port) {
    CURL* curl = curl_easy_init();
    HTTPResponse response;
    
    if (!curl) {
        throw std::runtime_error("Failed to initialize libcurl");
    }
    
    std::string url = "https://" + host + ":" + std::to_string(port) + "/";
    
    // Set common options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // First try with SSL verification enabled
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(curl);
    
    // If failed with SSL verification, try without it
    if (res != CURLE_OK) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        res = curl_easy_perform(curl);
    }
    
    if (res != CURLE_OK) {
        std::string error_msg = "CURL request failed: ";
        error_msg += curl_easy_strerror(res);
        
        // Special handling for common errors
        if (res == CURLE_COULDNT_RESOLVE_HOST) {
            error_msg += " (Check if the hostname/IP is correct and you have internet connection)";
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
            error_msg += " (Connection timed out. The server might be down or blocking requests)";
        } else if (res == CURLE_SSL_CONNECT_ERROR) {
            error_msg += " (SSL handshake failed. The server might be using an unsupported protocol)";
        }
        
        curl_easy_cleanup(curl);
        throw std::runtime_error(error_msg);
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    response.status_code = http_code;
    
    curl_easy_cleanup(curl);
    return response;
}