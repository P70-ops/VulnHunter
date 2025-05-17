#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include <string>

struct TLSInfo {
    std::string version;
    std::string cert_info;
};

TLSInfo check_tls(const std::string& host, int port);

#endif // TLS_UTILS_H