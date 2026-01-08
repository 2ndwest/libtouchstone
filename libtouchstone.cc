#include "libtouchstone.h"
#include "utils.h"
#include "sso.h"
#include <curl/curl.h>

namespace libtouchstone {

cpr::Session session(const char* cookie_file) {
    cpr::Session s;
    s.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0");
    auto curlHolder = s.GetCurlHolder();
    curl_easy_setopt(curlHolder->handle, CURLOPT_COOKIEFILE, cookie_file);
    curl_easy_setopt(curlHolder->handle, CURLOPT_COOKIEJAR, cookie_file);
    return s;
}

cpr::Response authenticate(cpr::Session& s, const char* url, const char* username,
                           const char* password, const AuthOptions& opts) {
    vlog(opts, "Authenticating to %s", url);

    // Make an initial request
    s.SetUrl(cpr::Url{url});
    cpr::Response r = s.Get();
    if (r.error) return r;

    std::string effective_url = r.url.str();

    // Check if already authenticated
    if (!contains(effective_url, "idp.mit.edu") && !contains(effective_url, "okta.mit.edu")) {
        vlog(opts, "libtouchstone: already authenticated (cookies valid)");
        return r;
    }

    // Okta flow
    if (contains(effective_url, "okta.mit.edu/app")) {
        vlog(opts, "libtouchstone: performing Okta flow");
        return perform_okta(s, r.text, username, password, opts);
    }

    // SSO redirect (cookies valid but need redirect)
    if (contains(effective_url, "idp.mit.edu/idp/profile/SAML2")) {
        vlog(opts, "libtouchstone: cookies valid, performing SSO redirect");
        return perform_final_idp_redirect(s, r.text, opts);
    }

    return make_error(OKTA_FLOW_ERROR, "Unknown authentication state");
}

}  // namespace libtouchstone
