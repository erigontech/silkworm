/*
   Copyright 2023 The Silkworm Authors

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

#include "enr_url.hpp"

#include <base64.h>

#include <stdexcept>

#include "enr_codec.hpp"

namespace silkworm::sentry::discovery::enr {

EnrRecord EnrUrl::parse(std::string_view url_str) {
    if (!url_str.starts_with("enr:"))
        throw std::invalid_argument("Invalid ENR URL format");
    auto data_str = base64_decode(url_str.substr(4), /* remove_linebreaks = */ false);
    ByteView data{reinterpret_cast<uint8_t*>(data_str.data()), data_str.size()};
    return EnrCodec::decode(data);
}

std::string EnrUrl::make(const EnrRecord& record, const EccKeyPair& key_pair) {
    Bytes data = EnrCodec::encode(record, key_pair);
    return "enr:" + base64_encode(data.data(), data.size(), /* url = */ true);
}

}  // namespace silkworm::sentry::discovery::enr
