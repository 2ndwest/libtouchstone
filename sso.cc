#include "sso.h"
#include "okta_parsing.h"
#include <cpr/util.h>

namespace libtouchstone {

using Json = jt::Json;

// IMPORTANT: We use PostRedirectFlags::NONE so that when we follow 301/302/303 redirects
// after a POST request, it converts the request method to GET (standard HTTP behavior).
// With POST_ALL (cpr default at time of writing), curl always maintains the POST method
// after redirects, which breaks the SSO flows that expect GET requests after redirects.
static const cpr::Redirect REDIRECT_CONFIG{cpr::PostRedirectFlags::NONE};

// Given Touchstone html, attempts to perform Touchstone SSO redirect
// by extracting form fields and POSTing to the right location. May be
// called without calling perform_okta first, if the user has valid cookies.
cpr::Response perform_final_idp_redirect(cpr::Session& s, const std::string& touchstone_html, const AuthOptions& opts) {
    ExtractedFormData form = extract_form(touchstone_html);

    if (form.action.empty() || form.fields.find("SAMLResponse") == form.fields.end()) {
        return make_error(PARSE_ERROR, "Failed to extract SAML form fields");
    }

    vlog(opts, "Shib: Posting SSO redirect to %s", form.action.c_str());

    s.SetUrl(cpr::Url{form.action});
    s.SetBody(cpr::Body{"RelayState=" + cpr::util::urlEncode(form.fields["RelayState"]) +
        "&SAMLResponse=" + cpr::util::urlEncode(form.fields["SAMLResponse"])});
    s.SetHeader(cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"}});
    s.SetRedirect(REDIRECT_CONFIG); // applies to the rest of the session
    cpr::Response r = s.Post();

    if (contains(r.url.str(), "idp.mit.edu")) return make_error(OKTA_FLOW_ERROR, "SAML redirect failed");

    vlog(opts, "Shib: SSO redirect successful!");
    return r;
}

// Performs Duo authentication, and returns the request that Duo responds with.
static cpr::Response perform_duo(cpr::Session& s, const std::string& duo_url,
                                  const std::string& duo_html, const AuthOptions& opts) {
    vlog(opts, "Duo: Starting authentication");

    std::string domain = regex_extract(duo_url, R"(https://([^/]+))");
    std::string sid = regex_extract(duo_url, R"(sid=([^&]+))");

    if (domain.empty() || sid.empty()) return make_error(DUO_FLOW_ERROR, "Can't extract sid and transaction from redirect URL");

    ExtractedFormData form = extract_form(duo_html, "plugin_form");
    std::string duo_tx = form.fields["tx"];
    std::string duo_akey = form.fields["akey"];
    std::string duo_xsrf = form.fields["_xsrf"];

    if (duo_tx.empty() || duo_akey.empty() || duo_xsrf.empty()) return make_error(DUO_FLOW_ERROR, "Unable to locate required Duo fields in first /frame/frameless/v4/auth call");

    vlog(opts, "Duo: Decoded Touchstone transaction/akey/xsrf from redirect");

    // Build the prompt data POST body
    std::string duo_prompt_data =
        "tx=" + cpr::util::urlEncode(duo_tx) +
        "&parent=None"
        "&_xsrf=" + cpr::util::urlEncode(duo_xsrf) +
        "&version=v4"
        "&akey=" + cpr::util::urlEncode(duo_akey) +
        "&has_session_trust_analysis_feature=False"
        "&session_trust_extension_id="
        "&java_version="
        "&screen_resolution_width=1920"
        "&screen_resolution_height=1080"
        "&color_depth=24"
        "&is_cef_browser=false"
        "&is_ipad_os=false"
        "&is_user_verifying_platform_authenticator_available=false"
        "&react_support=true";

    // Post to Duo to load required cookies and such
    s.SetUrl(cpr::Url{duo_url});
    s.SetBody(cpr::Body{duo_prompt_data});
    s.SetHeader(cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"}});
    s.SetRedirect(REDIRECT_CONFIG); // applies to the rest of the session
    cpr::Response hc = s.Post();

    // First one should be healthcheck
    if (!contains(hc.url.str(), "/frame/v4/preauth/healthcheck")) return make_error(DUO_FLOW_ERROR, "Didn't reach Duo healthcheck endpoint");

    // GET the data endpoint
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/preauth/healthcheck/data?sid=" + sid});
    s.Get();
    // and GET the return endpoint
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/return?sid=" + sid});
    s.Get();

    // Post again
    s.SetUrl(cpr::Url{duo_url});
    s.SetBody(cpr::Body{duo_prompt_data});
    cpr::Response r = s.Post();

    // Check if we're already authenticated (cached Duo cookie)
    if (contains(r.url.str(), "https://idp.mit.edu/idp/profile/SAML2/Redirect/SSO") ||
        contains(r.url.str(), "https://okta.mit.edu")) {
        // We're done!
        vlog(opts, "Duo: 2FA not required: Duo cookie cached. Returning to Touchstone");
        return r;
    }

    if (!contains(r.url.str(), "/frame/v4/auth/prompt")) return make_error(DUO_FLOW_ERROR, "Didn't reach the prompt Duo endpoint!");

    // Extract XSRF token from response
    std::string xsrf = regex_extract(r.text, R"(\"xsrf_token\":\s*\"([^\"]+)\")");
    if (xsrf.empty()) return make_error(DUO_FLOW_ERROR, "Unable to extract XSRF token from prompt GET");

    if (!opts.block) return make_error(WOULD_BLOCK, "Second factor auth required, but blocking is not allowed");

    vlog(opts, "Duo: Second factor auth required: requested Duo auth page");

    cpr::Header extra_prompt_headers{
        {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"},
        {"Referer", "https://" + domain + "/frame/v4/auth/prompt?sid=" + sid},
        {"X-Requested-With", "XMLHttpRequest"},
        {"X-Xsrftoken", xsrf},
        {"Origin", "https://" + domain}
    };

    // Get the device ID
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/auth/prompt/data?post_auth_action=OIDC_EXIT&sid=" + sid});
    s.SetHeader(extra_prompt_headers);
    r = s.Get();

    auto [parse_ok, prompt_data] = Json::parse(r.text);
    if (parse_ok != Json::success || prompt_data["stat"].getString() != "OK") return make_error(DUO_FLOW_ERROR, "Unable to fetch Duo prompt data");
    std::string device_id = prompt_data["response"]["phones"][0]["key"].getString();

    // POST to send the push
    const char* factor = (opts.twofactor == 1) ? "Phone+Call" : "Duo+Push";
    if (opts.twofactor == 1) return make_error(DUO_FLOW_ERROR, "Phone call 2FA factor is not currently supported"); // TODO
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/prompt"});
    s.SetBody(cpr::Body{"device=phone1&factor=" + std::string(factor) + "&postAuthDestination=OIDC_EXIT&sid=" + sid});
    s.SetHeader(extra_prompt_headers);
    r = s.Post();

    vlog(opts, "Duo: Requested second factor authentication (%s)", factor);

    auto [push_ok, prompt_response] = Json::parse(r.text);
    if (push_ok != Json::success || prompt_response["stat"].getString() != "OK") return make_error(DUO_FLOW_ERROR, "Unable to send two-factor request");

    std::string txid = prompt_response["response"]["txid"].getString();
    vlog(opts, "Duo: Sent %s request, waiting for approval...", factor);

    // Do a first request (this returns the info 'Pushed a login request to your device')
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/status"});
    s.SetBody(cpr::Body{"sid=" + sid + "&txid=" + txid});
    s.SetHeader(extra_prompt_headers);
    r = s.Post();

    const char* expected_status = (opts.twofactor == 1) ? "calling" : "pushed";

    auto [stat1_ok, stat1_json] = Json::parse(r.text);
    if (stat1_ok != Json::success || stat1_json["response"]["status_code"].getString() != expected_status) return make_error(DUO_FLOW_ERROR, "Second-factor auth failed");

    vlog(opts, "Duo: Successfully pushed Duo push request. Blocking until response...");

    // Second status check (blocks until user responds)
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/status"});
    s.SetBody(cpr::Body{"sid=" + sid + "&txid=" + txid});
    s.SetHeader(extra_prompt_headers);
    r = s.Post();

    auto [stat2_ok, post_prompt_response] = Json::parse(r.text);
    if (stat2_ok != Json::success ||
        post_prompt_response["stat"].getString() != "OK" ||
        post_prompt_response["response"]["status_code"].getString() != "allow")
        return make_error(DUO_FLOW_ERROR, "User declined prompt or prompt timed out");

    vlog(opts, "Duo: Second factor auth successful!");

    // Post to the log endpoint
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/prompt/v4/log_analytic"});
    s.SetBody(cpr::Body{
        "action=1"
        "&page=/frame/v4/auth/prompt"
        "&target=trust+browser:+yes"
        "&browser_language=en-US"
        "&prompt_language=en"
        "&is_error=false"
        "&error_message=undefined"
        "&auth_method=" + std::string(factor) +
        "&auth_state=AUTH_SUCCESS"
        "&sid=" + sid
    });
    s.SetHeader(extra_prompt_headers);
    r = s.Post();

    vlog(opts, "Duo: Exiting back to Touchstone");

    // Get the AUTH token
    s.SetUrl(cpr::Url{"https://" + domain + "/frame/v4/oidc/exit"});
    s.SetBody(cpr::Body{"sid=" + sid +
        "&txid=" + txid +
        "&factor=" + factor +
        "&device_key=" + device_id +
        "&_xsrf=" + cpr::util::urlEncode(xsrf) +
        "&dampen_choice=true"});
    s.SetHeader(cpr::Header{
        {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"},
        {"Origin", "https://" + domain},
        {"Referer", "https://" + domain + "/frame/v4/auth/prompt?sid=" + sid}
    });
    r = s.Post();

    vlog(opts, "Duo: Returned to Okta");
    return r;
}

// Performs Touchstone login via thew new Okta. This handles redirects to/from Duo.
cpr::Response perform_okta(cpr::Session& s, const std::string& touchstone_proxy_response,
                           const char* user, const char* pass, const AuthOptions& opts) {
    vlog(opts, "Okta: Starting authentication flow");

    // Extract state token
    std::string state_token = extract_state_token(touchstone_proxy_response);
    if (state_token.empty()) return make_error(PARSE_ERROR, "Okta: Failed to extract state token from page");

    vlog(opts, "Okta: Extracted state token");

    // Call introspect endpoint
    s.SetUrl(cpr::Url{"https://okta.mit.edu/idp/idx/introspect"});
    s.SetBody(cpr::Body{"{\"stateToken\":\"" + state_token + "\"}"});
    s.SetHeader(cpr::Header{{"Content-Type", "application/ion+json; okta-version=1.0.0"}});
    s.SetRedirect(REDIRECT_CONFIG); // applies to the rest of the session
    cpr::Response r = s.Post();

    // # Only allow up to 5 remediations for now
    for (int i = 0; i < 5; i++) {
        if (r.status_code != 200) return make_error(OKTA_FLOW_ERROR, "Failed Okta remediation request");

        // If the URL is a Duo URL, we're done (url_matches_duo)
        if (!regex_extract(r.url.str(), R"(https://([^/]+)([^?]+)\?sid=([^&]+)&tx=(.*))").empty()) break;

        auto [parse_ok, remediation_data] = Json::parse(r.text);
        if (parse_ok != Json::success) return make_error(PARSE_ERROR, "Okta: Failed to parse introspect response");

        Remediation rem = select_remediation(remediation_data["remediation"]["value"], user, pass);
        if (!rem.valid) return make_error(OKTA_FLOW_ERROR, "Okta: No valid remediation found");

        vlog(opts, "Okta (%s): %sing to %s", rem.name.c_str(), rem.method.c_str(), rem.url.c_str());

        if (rem.method == "POST") {
            s.SetUrl(cpr::Url{rem.url});
            s.SetBody(cpr::Body{rem.data.toString()});
            s.SetHeader(cpr::Header{{"Content-Type", "application/json"}});
            r = s.Post();
        } else if (rem.method == "GET") {
            s.SetUrl(cpr::Url{rem.url});
            r = s.Get();
        }
    }

    // Duo flow
    cpr::Response duo_response = perform_duo(s, r.url.str(), r.text, opts);
    if (duo_response.error) return duo_response;

    // Extract the OktaData from the proxy request
    state_token = extract_state_token(duo_response.text);
    if (state_token.empty()) return make_error(PARSE_ERROR, "Failed to extract state token after Duo");

    // Call back to the introspect endpoint to get the redirect
    s.SetUrl(cpr::Url{"https://okta.mit.edu/idp/idx/introspect"});
    s.SetBody(cpr::Body{"{\"stateToken\":\"" + state_token + "\"}"});
    s.SetHeader(cpr::Header{{"Content-Type", "application/ion+json; okta-version=1.0.0"}});
    r = s.Post();
    if (r.status_code != 200) return make_error(OKTA_FLOW_ERROR, "Failed to extract Okta redirect URL!");

    auto [ok, redirect_data] = Json::parse(r.text);
    if (ok != Json::success) return make_error(PARSE_ERROR, "Failed to parse post-Duo introspect");

    if (!redirect_data.contains("success") ||
        !redirect_data["success"].contains("name") ||
        redirect_data["success"]["name"].getString() != "success-redirect" ||
        !redirect_data["success"].contains("href")) {
        return make_error(OKTA_FLOW_ERROR, "Failed to extract Okta redirect URL!");
    }

    vlog(opts, "Okta (shib-proxy): Obtaining SAML response...");
    s.SetUrl(cpr::Url{redirect_data["success"]["href"].getString()});
    r = s.Get();

    // Parse Shibboleth proxy form
    ExtractedFormData proxy_form = extract_form(r.text, "appForm");
    if (proxy_form.action.empty()) return make_error(PARSE_ERROR, "Unable to extract the Shibboleth proxy form!");

    // Post to Shibboleth proxy
    s.SetUrl(cpr::Url{proxy_form.action});
    s.SetBody(cpr::Body{
        "SAMLResponse=" + cpr::util::urlEncode(proxy_form.fields["SAMLResponse"]) +
        "&RelayState=" + cpr::util::urlEncode(proxy_form.fields["RelayState"])
    });
    s.SetHeader(cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"}});
    r = s.Post();

    if (r.status_code != 200) return make_error(OKTA_FLOW_ERROR, "Failed to redirect to Shibboleth");

    vlog(opts, "Okta (shib-proxy): redirected to Shibboleth successfully");

    return perform_final_idp_redirect(s, r.text, opts);
}

}  // namespace libtouchstone
