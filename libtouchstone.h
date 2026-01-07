#pragma once

#include <cpr/cpr.h>

namespace libtouchstone {

struct AuthOptions {
    const char* cookie_file = "cookies.txt";
    bool verbose = false;
    bool block = true;     // false = error instead of waiting for 2FA
    int twofactor = 0;     // 0 = Duo Push, 1 = Phone Call (not implemented currently)
};

// Create a session configured for Touchstone auth with cookie persistence.
cpr::Session session(const char* cookie_file = "cookies.txt");

// Authenticate to a Touchstone-protected URL.
// Uses the provided session (which can be reused for subsequent requests).
// On success: response has target page, session retains auth cookies.
// On error: response.error is set.
cpr::Response authenticate(
    cpr::Session& s,
    const char* url,
    const char* username,
    const char* password,
    const AuthOptions& opts = {});

}  // namespace libtouchstone
