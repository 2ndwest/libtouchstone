#include "sso.h"
#include "okta_parsing.h"
#include <cpr/util.h>
#include <chrono>
#include <thread>

namespace libtouchstone {

using Json = jt::Json;

// IMPORTANT: We use PostRedirectFlags::NONE so that when we follow 301/302/303 redirects
// after a POST request, it converts the request method to GET (standard HTTP behavior).
// With POST_ALL (cpr default at time of writing), cpr always maintains the POST method
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
    s.SetBody(cpr::Body{
        "RelayState=" + cpr::util::urlEncode(form.fields["RelayState"]) +
        "&SAMLResponse=" + cpr::util::urlEncode(form.fields["SAMLResponse"])
    });
    s.SetHeader(cpr::Header{{"Content-Type", "application/x-www-form-urlencoded"}});
    s.SetRedirect(REDIRECT_CONFIG); // applies to the rest of the session
    cpr::Response r = s.Post();

    // Check if we got another SAML form (chained redirect through idp)
    if (contains(r.url.str(), "idp.mit.edu")) {
        if (contains(r.text, "SAMLResponse")) {
            vlog(opts, "Shib: Got another SAML form, recursing...");
            return perform_final_idp_redirect(s, r.text, opts);
        }
        return make_error(OKTA_FLOW_ERROR, "SSO redirect unsuccessful");
    }

    vlog(opts, "Shib: SSO redirect successful!");
    return r;
}

// Duo's Universal Prompt is a JavaScript app, so instead of scraping it we drive the
// JSON API it talks to. Every endpoint hangs off https://<host>/prompt/<akey>, is
// authenticated by the authkey embedded in the page, and replies with a
// {"stat": "OK", "response": {...}} envelope.

// Duo's JS collects these from the browser; a fixed set is fine for a headless client.
static const char* DUO_BROWSER_FEATURES =
    R"({"touch_supported":false,"platform_authenticator_status":"unavailable",)"
    R"("webauthn_supported":false,"screen_resolution_height":1080,)"
    R"("screen_resolution_width":1920,"screen_color_depth":24,)"
    R"("is_uvpa_available":false,"client_capabilities_uvpa":false})";

// True once Okta has handed us off to a Duo Universal Prompt page.
static bool is_duo_prompt(const std::string& url) {
    return std::regex_search(url, std::regex(R"(^https://[^/]+/prompt/\w+)"));
}

// Performs Duo authentication, and returns the request that Duo responds with.
static cpr::Response perform_duo(cpr::Session& s, const std::string& duo_url,
                                 const std::string& duo_html, const AuthOptions& opts) {
    vlog(opts, "Duo: Starting Universal Prompt authentication");

    std::string host    = regex_extract(duo_url,  R"(https://([^/]+))");
    std::string akey    = regex_extract(duo_html, R"rx(data-akey="([^"]+)")rx");
    std::string authkey = regex_extract(duo_html, R"rx(data-authkey="([^"]+)")rx");
    std::string trace   = regex_extract(duo_html, R"rx(data-req-trace-group="([^"]*)")rx");

    if (akey.empty() || authkey.empty())
        return make_error(DUO_FLOW_ERROR, "Unable to locate Duo akey/authkey on the prompt page");

    const std::string base  = "https://" + host + "/prompt/" + akey;
    const std::string auth  = "authkey=" + cpr::util::urlEncode(authkey);
    const std::string feats = "browser_features=" + cpr::util::urlEncode(DUO_BROWSER_FEATURES);

    // Issue one prompt-API call, unwrapping the envelope into `out`. A body makes it a
    // POST; like Duo's own client, we only send a Content-Type when there is one.
    Json out;
    auto call = [&](const std::string& url, const std::string& body = "") {
        cpr::Header headers{{"X-Duo-Req-Trace-Group", trace}};
        if (!body.empty()) headers["Content-Type"] = "application/json";

        s.SetUrl(cpr::Url{url});
        s.SetBody(cpr::Body{body});
        s.SetHeader(headers);
        cpr::Response r = body.empty() ? s.Get() : s.Post();
        auto [parse_ok, envelope] = Json::parse(r.text);
        if (parse_ok != Json::success || envelope["stat"].getString() != "OK") {
            vlog(opts, "Duo: %s -> HTTP %ld: %.300s", url.c_str(), r.status_code, r.text.c_str());
            return false;
        }
        out = std::move(envelope["response"]);
        return true;
    };

    // Priming /auth/payload is mandatory: /pre_authn/evaluation 400s without it.
    if (!call(base + "/auth/payload?" + auth + "&" + feats))
        return make_error(DUO_FLOW_ERROR, "Duo rejected the initial payload request");

    // local_trust_choice=undecided declines the "trust this browser" offer, so no
    // trusted-device cookie is minted and a second factor is required every run.
    if (!call(base + "/pre_authn/evaluation?" + auth + "&" + feats + "&local_trust_choice=undecided"))
        return make_error(DUO_FLOW_ERROR, "Duo rejected the pre-authentication request");

    // Anything other than "auth" means Duo is already satisfied (e.g. a remembered
    // device), so we can skip straight to collecting the exit URL.
    if (out["action"].getString() == "auth") {
        if (opts.twofactor == 1) return make_error(DUO_FLOW_ERROR, "Phone call 2FA factor is not currently supported"); // TODO
        if (!opts.block) return make_error(WOULD_BLOCK, "Second factor auth required, but blocking is not allowed");

        std::string pkey;
        for (auto& factor : out["auth_factors_context"]["available_unified_auth_factors"]["factors"].getArray()) {
            if (factor["factor_type"].getString() == "push") {
                pkey = factor["device_info"]["pkey"].getString();
                break;
            }
        }
        if (pkey.empty()) return make_error(DUO_FLOW_ERROR, "No Duo Push capable device is enrolled");

        Json push;
        push["authkey"] = authkey;
        push["pkey"] = pkey;
        push["otp_code"] = nullptr;
        if (!call(base + "/auth/factors/push/auth", push.toString()))
            return make_error(DUO_FLOW_ERROR, "Unable to send two-factor request");

        vlog(opts, "Duo: Sent Duo Push request, waiting for approval...");

        // The status endpoint long-polls, reporting "STATUS" for as long as it waits;
        // the sleep only guards against it returning immediately and spinning us.
        const std::string status_url = base + "/auth/factors/push/status?" + auth +
            "&push_txid=" + cpr::util::urlEncode(out["push_txid"].getString()) +
            "&saw_good_news=false";

        std::string status;
        for (int i = 0; i < 60; i++) {
            if (i) std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!call(status_url)) return make_error(DUO_FLOW_ERROR, "Duo push status request failed");

            status = out["result"]["result"].getString();
            if (status != "STATUS") break;  // SUCCESS, or a terminal outcome
        }
        if (status != "SUCCESS") return make_error(DUO_FLOW_ERROR, "User declined prompt or prompt timed out");

        vlog(opts, "Duo: Second factor auth successful!");
    }

    if (!call(base + "/auth/finalize_auth?" + auth))
        return make_error(DUO_FLOW_ERROR, "Duo refused to finalize authentication");

    std::string exit_url = out["url"].getString();
    if (exit_url.empty()) return make_error(DUO_FLOW_ERROR, "Duo did not return an exit URL");

    vlog(opts, "Duo: Exiting back to Okta");

    s.SetUrl(cpr::Url{exit_url});
    s.SetBody(cpr::Body{""});
    s.SetHeader(cpr::Header{});
    return s.Get();
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

    Json user_remediation_data;
    user_remediation_data["identifier"] = std::string(user) + "@mit.edu";
    user_remediation_data["rememberMe"] = true;
    user_remediation_data["credentials"]["passcode"] = std::string(pass);

    // Only allow up to 5 remediations for now
    for (int i = 0; i < 5; i++) {
        if (r.status_code != 200) return make_error(OKTA_FLOW_ERROR, "Failed Okta remediation request");

        // Okta serves HTML rather than IDX JSON once it hands off, either to Duo or
        // (when 2FA is already satisfied) straight back to itself.
        auto [parse_ok, remediation_data] = Json::parse(r.text);
        if (parse_ok != Json::success) {
            if (is_duo_prompt(r.url.str()) || !extract_state_token(r.text).empty()) break;
            return make_error(PARSE_ERROR, "Okta: response was neither IDX JSON nor a recognised handoff");
        }

        Remediation rem = select_remediation(remediation_data["remediation"]["value"], user_remediation_data);
        if (!rem.valid) return make_error(OKTA_FLOW_ERROR, "Okta: No valid remediation found");

        vlog(opts, "Okta (%s): %sing to %s", rem.name.c_str(), rem.http_method.c_str(), rem.url.c_str());

        if (rem.http_method == "POST") {
            s.SetUrl(cpr::Url{rem.url});
            s.SetBody(cpr::Body{rem.data.toString()});
            s.SetHeader(cpr::Header{{"Content-Type", "application/json"}});
            r = s.Post();
        } else if (rem.http_method == "GET") {
            s.SetUrl(cpr::Url{rem.url});
            r = s.Get();
        }
    }

    // Duo flow (skipped entirely when Okta did not need a second factor)
    if (is_duo_prompt(r.url.str())) {
        r = perform_duo(s, r.url.str(), r.text, opts);
        if (r.error) return r;
    }

    // Extract the OktaData from the proxy request
    state_token = extract_state_token(r.text);
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
