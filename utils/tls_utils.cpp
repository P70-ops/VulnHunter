#include "../include/tls_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>
#include <sstream>
#include <stdexcept>

using namespace std;

string get_ssl_version_string(int version) {
    switch (version) {
        case TLS1_VERSION: return "TLS 1.0";
        case TLS1_1_VERSION: return "TLS 1.1";
        case TLS1_2_VERSION: return "TLS 1.2";
        case TLS1_3_VERSION: return "TLS 1.3";
        case SSL3_VERSION: return "SSL 3.0";
        default: return "Unknown (" + to_string(version) + ")";
    }
}

string get_certificate_info(X509* cert) {
    if (!cert) return "No certificate";
    
    ostringstream oss;
    BIO* bio = BIO_new(BIO_s_mem());
    
    // Subject
    X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    char subject[256] = {0};
    BIO_read(bio, subject, sizeof(subject)-1);
    oss << "Subject: " << subject << "\n";
    BIO_reset(bio);
    
    // Issuer
    X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE);
    char issuer[256] = {0};
    BIO_read(bio, issuer, sizeof(issuer)-1);
    oss << "Issuer: " << issuer << "\n";
    BIO_reset(bio);
    
    // Validity
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
    char not_before[64] = {0};
    BIO_read(bio, not_before, sizeof(not_before)-1);
    oss << "Valid From: " << not_before << "\n";
    BIO_reset(bio);
    
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
    char not_after[64] = {0};
    BIO_read(bio, not_after, sizeof(not_after)-1);
    oss << "Valid Until: " << not_after << "\n";
    BIO_reset(bio);
    
    // Signature algorithm
    int sig_nid = X509_get_signature_nid(cert);
    oss << "Signature Algorithm: " << OBJ_nid2ln(sig_nid) << "\n";
    
    // Key information (OpenSSL 3.0+ compatible)
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (pubkey) {
        int key_type = EVP_PKEY_get_id(pubkey);
        int bits = EVP_PKEY_get_bits(pubkey);
        
        if (key_type == EVP_PKEY_RSA) {
            oss << "Key: RSA " << bits << " bits\n";
            
            // Get RSA parameters if needed
            BIGNUM *n = nullptr, *e = nullptr;
            if (EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_N, &n) &&
                EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
                char* n_hex = BN_bn2hex(n);
                char* e_hex = BN_bn2hex(e);
                oss << "RSA Modulus (first 16 bytes): " << string(n_hex, min(32, (int)strlen(n_hex))) << "...\n";
                oss << "RSA Exponent: " << e_hex << "\n";
                OPENSSL_free(n_hex);
                OPENSSL_free(e_hex);
                BN_free(n);
                BN_free(e);
            }
        }
        else if (key_type == EVP_PKEY_EC) {
            oss << "Key: EC " << bits << " bits\n";
            
            // Get EC curve name
            char curve_name[80] = {0};
            size_t curve_name_len = 0;
            if (EVP_PKEY_get_utf8_string_param(pubkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                              curve_name, sizeof(curve_name), &curve_name_len)) {
                oss << "Curve: " << curve_name << "\n";
            }
        }
        EVP_PKEY_free(pubkey);
    }
    
    // Additional certificate extensions
    oss << "Extensions:\n";
    for (int i = 0; i < X509_get_ext_count(cert); i++) {
        X509_EXTENSION* ext = X509_get_ext(cert, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        BIO_printf(bio, "  %s: ", OBJ_nid2ln(OBJ_obj2nid(obj)));
        X509V3_EXT_print(bio, ext, 0, 0);
        BIO_printf(bio, "\n");
        
        char ext_info[256] = {0};
        BIO_read(bio, ext_info, sizeof(ext_info)-1);
        oss << ext_info;
        BIO_reset(bio);
    }
    
    BIO_free(bio);
    return oss.str();
}

TLSInfo check_tls(const string& host, int port) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        throw runtime_error("Failed to create SSL context");
    }
    
    // Modern security settings
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    BIO* bio = BIO_new_connect((host + ":" + to_string(port)).c_str());
    if (!bio) {
        SSL_CTX_free(ctx);
        throw runtime_error("Failed to create BIO");
    }
    
    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        throw runtime_error("Failed to connect");
    }
    
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        throw runtime_error("Failed to create SSL");
    }
    
    SSL_set_bio(ssl, bio, bio);
    
    TLSInfo info;
    
    if (SSL_connect(ssl) <= 0) {
        info.version = "Failed to establish SSL connection";
        info.cert_info = "No certificate information available";
        ERR_print_errors_fp(stderr);
    } else {
        // Get SSL/TLS version
        int version = SSL_version(ssl);
        info.version = get_ssl_version_string(version);
        
        // Get certificate information
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            info.cert_info = get_certificate_info(cert);
            X509_free(cert);
        } else {
            info.cert_info = "No certificate presented by server";
        }
        
        // Additional security checks
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            info.cert_info += "\nCertificate Verification Failed: " + 
                             string(X509_verify_cert_error_string(verify_result));
        }
    }
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return info;
}