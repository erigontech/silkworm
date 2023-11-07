/*
   Copyright 2022 The Silkworm Authors

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
#include <stdexcept>
#include <string>

#include <gsl/narrow>

namespace silkworm::sentry {

using namespace std;

EnodeUrl::EnodeUrl(string_view url_str)
    : public_key_(Bytes{}) {
    regex url_regex(
        R"(enode://([0-9a-f]+)@((?:\d+\.){3}\d+)\:(\d+))",
        regex::icase);
    match_results<std::string_view::const_iterator> match;
    if (!regex_match(url_str.cbegin(), url_str.cend(), match, url_regex)) {
        throw invalid_argument("Invalid enode URL format");
    }

    string pub_key_hex = match[1];
    string ip_str = match[2];
    string port_str = match[3];

    auto ip = boost::asio::ip::make_address(ip_str);

    auto port = gsl::narrow<uint16_t>(std::stoul(port_str));

    public_key_ = EccPublicKey::deserialize_hex(pub_key_hex);
    ip_ = ip;
    port_disc_ = port;
    port_rlpx_ = port;
}

string EnodeUrl::to_string() const {
    ostringstream out;
    out << "enode://";
    out << public_key_.hex() << "@";
    out << ip_.to_string();
    out << ":" << port_rlpx_;

    if (port_disc_ != port_rlpx_) {
        out << "?discport=" << port_disc_;
    }

    return out.str();
}

bool EnodeUrl::operator<(const EnodeUrl& other) const {
    return to_string() < other.to_string();
}

}  // namespace silkworm::sentry
