/*
Copyright 2020-2022 The Silkworm Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "enode_url.hpp"
#include <regex>
#include <sstream>
#include <boost/lexical_cast.hpp>

namespace silkworm::sentry {

using namespace std;

EnodeUrl::EnodeUrl(const string& url_str) {
    regex url_regex(
        R"(enode://([0-9a-f]+)@((?:\d+\.){3}\d+)\:(\d+))",
        regex::icase
    );
    smatch match;
    if (!regex_match(url_str, match, url_regex)) {
        throw invalid_argument("Invalid enode URL format");
    }

    string pub_key_hex = match[1];
    string ip_str = match[2];
    string port_str = match[3];

    auto ip = boost::asio::ip::address::from_string(ip_str);

    auto port = boost::lexical_cast<uint16_t>(port_str);

    pub_key_hex_ = pub_key_hex;
    ip_ = ip;
    port_ = port;
}

string EnodeUrl::to_string() const {
    ostringstream out;
    out << "enode://";
    out << pub_key_hex_ << "@";
    out << ip_.to_string();
    out << ":" << port_;
    return out.str();
}


}  // namespace silkworm::sentry
