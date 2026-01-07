# libtouchstone

libtouchstone is a C++ port of [touchstone-auth](https://github.com/meson800/touchstone-auth),
a library for programmatically authenticating to apps protected by MIT's Touchstone SSO.
Built on top of the ergonomic [cpr](https://github.com/libcpr/cpr) requests library,
which wraps [libcurl](https://curl.se/libcurl/) under the hood.

It handles the full authentication flow: Okta login, Duo 2FA push
notifications, SAML redirects, and cookie persistence for session reuse.

## Usage

See [example.cc](example.cc) and/or [libtouchstone.h](libtouchstone.h) for more.

```cpp
#include "libtouchstone.h"

int main() {
    auto session = libtouchstone::session("cookies.txt");
    auto response = libtouchstone::authenticate(
        session,
        "https://atlas.mit.edu/atlas/Main.action",
        "yourkerb",
        "password");

    printf("Got %zu bytes from %s\n", response.text.size(), response.url.str().c_str());
}
```

## Building

```sh
cmake -B build
cmake --build build
```

## Dependencies

- [cpr](https://github.com/libcpr/cpr) - C++ HTTP client
- [lexbor](https://github.com/lexbor/lexbor) - HTML5 parser
- [json.cpp](https://github.com/jart/json.cpp) - JSON parser
