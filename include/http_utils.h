#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <string>
#include <vector>

struct HTTPResponse {
    int status_code;
    std::vector<std::string> headers;
    std::string body;
};

HTTPResponse fetch_http_response(const std::string& host, int port);

#endif // HTTP_UTILS_H