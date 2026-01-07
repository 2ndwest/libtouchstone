#pragma once

#include "libtouchstone.h"
#include <cstdarg>
#include <cstdio>

namespace libtouchstone {

enum AuthError {
    OK = 0,
    OKTA_FLOW_ERROR = 1000,
    DUO_FLOW_ERROR = 1001,
    WOULD_BLOCK = 1002,
    PARSE_ERROR = 1003,
};

inline cpr::Response make_error(AuthError code, const char* msg) {
    cpr::Response r;
    r.error.code = static_cast<cpr::ErrorCode>(code);
    r.error.message = msg;
    return r;
}


inline void vlog(const AuthOptions& opts, const char* fmt, ...) {
    if (!opts.verbose) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

cpr::Response perform_okta(cpr::Session& s, const std::string& touchstone_proxy_response,
                           const char* user, const char* pass, const AuthOptions& opts);

cpr::Response perform_final_idp_redirect(cpr::Session& s, const std::string& html, const AuthOptions& opts);

cpr::Response make_error(AuthError code, const char* msg);

void vlog(const AuthOptions& opts, const char* fmt, ...);

}  // namespace libtouchstone
