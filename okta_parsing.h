#pragma once

#include "utils.h"
#include <json.h>
#include <lexbor/html/parser.h>
#include <lexbor/dom/interfaces/element.h>
#include <lexbor/dom/interfaces/attr.h>
#include <string>
#include <vector>
#include <map>

namespace libtouchstone {

using Json = jt::Json;

struct Remediation {
    std::string name;
    std::string url;
    std::string http_method;
    Json data;
    bool valid = false;
};

inline const std::vector<std::string> BLACKLISTED_REMEDIATIONS = {"unlock-account"};

// Given an Okta set of remediations and our available data,
// returns a struct representing which remediation to take
inline Remediation select_remediation(Json remediations, Json& available_data) {
    for (auto& remediation_option : remediations.getArray()) {
        std::string name = remediation_option["name"].getString();

        // Check if blacklisted
        bool blacklisted = false;
        for (const auto& b : BLACKLISTED_REMEDIATIONS) {
            if (name == b) {
                blacklisted = true;
                break;
            }
        }
        if (blacklisted) continue;

        std::string url = remediation_option["href"].getString();
        std::string method = remediation_option["method"].getString();

        // Check if we have all of the entries
        Json remediation_data;
        bool complete = true;
        if (remediation_option.contains("value")) {
            for (auto& value : remediation_option["value"].getArray()) {
                std::string value_name = value["name"].getString();
                if (value.contains("value")) {
                    remediation_data[value_name] = value["value"];
                } else {
                    if (!available_data.contains(value_name)) {
                        complete = false;
                        break;
                    }
                    remediation_data[value_name] = available_data[value_name];
                }
            }
            if (!complete) {
                continue;
            }
        }
        // At this point, we have a complete remediation!
        return Remediation{name, url, method, std::move(remediation_data), true};
    }
    return Remediation{};
}

inline std::string extract_state_token(const std::string& html) {
    // Find oktaData = {...};
    std::string okta_data = regex_extract(html, R"(oktaData\s*=\s*(\{.*?\};))");
    if (okta_data.empty()) return "";

    // Extract stateToken
    std::string raw_token = regex_extract(okta_data, R"(\"idpDiscovery\":.*?\"stateToken\":\s*\"([^\"]+)\")");
    if (raw_token.empty()) return "";

    // Decode weird JS \xHH escapes and such. Done in python
    // with: <...>.encode('utf-8').decode('unicode_escape')
    std::string json_wrapper = "{\"v\":\"" + raw_token + "\"}";
    auto [status, parsed] = Json::parse(json_wrapper);
    if (status != Json::success) return "";

    return parsed["v"].getString();
}

struct ExtractedFormData {
    std::string action;
    std::map<std::string, std::string> fields;
};

// Extract HTML form using lexbor.
// If form_id is nullptr (the default), extracts the first form found in the document.
// If form_id is provided, searches for a form element with that specific id attribute.
inline ExtractedFormData extract_form(const std::string& html, const char* form_id = nullptr) {
    ExtractedFormData result;

    lxb_html_document_t* doc = lxb_html_document_create();
    if (!doc) return result;

    lxb_status_t status = lxb_html_document_parse(doc,
        (const lxb_char_t*)html.c_str(), html.size());
    if (status != LXB_STATUS_OK) {
        lxb_html_document_destroy(doc);
        return result;
    }

    // Find form element
    lxb_dom_element_t* form = nullptr;
    if (form_id) {
        lxb_dom_collection_t* forms = lxb_dom_collection_make(&doc->dom_document, 16);
        lxb_dom_elements_by_tag_name(lxb_dom_interface_element(doc->body),
            forms, (const lxb_char_t*)"form", 4);
        for (size_t i = 0; i < lxb_dom_collection_length(forms); i++) {
            lxb_dom_element_t* f = lxb_dom_collection_element(forms, i);
            size_t len;
            const lxb_char_t* id = lxb_dom_element_get_attribute(f,
                (const lxb_char_t*)"id", 2, &len);
            if (id && std::string((const char*)id, len) == form_id) {
                form = f;
                break;
            }
        }
        lxb_dom_collection_destroy(forms, true);
    } else {
        lxb_dom_collection_t* forms = lxb_dom_collection_make(&doc->dom_document, 16);
        lxb_dom_elements_by_tag_name(lxb_dom_interface_element(doc->body),
            forms, (const lxb_char_t*)"form", 4);
        if (lxb_dom_collection_length(forms) > 0) {
            form = lxb_dom_collection_element(forms, 0);
        }
        lxb_dom_collection_destroy(forms, true);
    }

    if (!form) {
        lxb_html_document_destroy(doc);
        return result;
    }

    // Extract action
    size_t action_len;
    const lxb_char_t* action = lxb_dom_element_get_attribute(form,
        (const lxb_char_t*)"action", 6, &action_len);
    if (action) {
        result.action = std::string((const char*)action, action_len);
    }

    // Extract input fields
    lxb_dom_collection_t* inputs = lxb_dom_collection_make(&doc->dom_document, 32);
    lxb_dom_elements_by_tag_name(form, inputs, (const lxb_char_t*)"input", 5);

    for (size_t i = 0; i < lxb_dom_collection_length(inputs); i++) {
        lxb_dom_element_t* input = lxb_dom_collection_element(inputs, i);

        size_t name_len, value_len;
        const lxb_char_t* name = lxb_dom_element_get_attribute(input,
            (const lxb_char_t*)"name", 4, &name_len);
        const lxb_char_t* value = lxb_dom_element_get_attribute(input,
            (const lxb_char_t*)"value", 5, &value_len);

        if (name) {
            std::string field_name((const char*)name, name_len);
            std::string field_value = value ? std::string((const char*)value, value_len) : "";
            result.fields[field_name] = field_value;
        }
    }

    lxb_dom_collection_destroy(inputs, true);
    lxb_html_document_destroy(doc);
    return result;
}

}  // namespace libtouchstone
