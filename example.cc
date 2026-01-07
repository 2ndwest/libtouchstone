#include "libtouchstone.h"
#include "json.cpp"
#include <cstdio>
#include <fstream>

using namespace std;
using Json = jt::Json;

int main(int argc, char* argv[]) {
    ifstream creds_file("credentials.json");
    if (!creds_file) {
        fprintf(stderr, "Failed to open credentials.json\n");
        return 1;
    }

    string creds_str{istreambuf_iterator<char>(creds_file), {}};

    auto [status, creds] = Json::parse(creds_str);
    if (status != Json::success) {
        fprintf(stderr, "Failed to parse credentials.json\n");
        return 1;
    }

    string username = creds["username"].getString();
    string password = creds["password"].getString();

    libtouchstone::AuthOptions opts;
    opts.verbose = true;

    // Use command line arg as URL, or default to classrooms.mit.edu/classrooms/quickroom.
    const char* url = argc > 1 ? argv[1] : "https://classrooms.mit.edu/classrooms/quickroom";

    {
        auto s = libtouchstone::session(opts.cookie_file);
        cpr::Response r = libtouchstone::authenticate(s, url, username.c_str(), password.c_str(), opts);

        if (r.error) {
            fprintf(stderr, "Auth failed: %s\n", r.error.message.c_str());
            return 1;
        }

        printf("Authenticated! Got %zu bytes from %s\n", r.text.size(), r.url.str().c_str());
        printf("Raw response:\n%.256s\n", r.text.c_str());
    } // Session and Response destroyed here -> cookies flushed.

    // Subsequent requests use a fresh session (cookies loaded from file)
    auto s2 = libtouchstone::session(opts.cookie_file);
    s2.SetUrl(cpr::Url{url});
    auto r2 = s2.Get();
    printf("Subsequent request: %ld status, %zu bytes\n", r2.status_code, r2.text.size());
    printf("Raw response:\n%.256s\n", r2.text.c_str());

    return 0;
}
