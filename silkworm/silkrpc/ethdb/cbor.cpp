/*
    Copyright 2021 The Silkrpc Authors

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

#include "cbor.hpp"

#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc {

bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Log>& logs) {
    if (bytes.size() == 0) {
        return false;
    }
    auto json = nlohmann::json::from_cbor(bytes);
    SILKRPC_TRACE << "cbor_decode<std::vector<Log>> json: " << json.dump() << "\n";
    if (json.is_array()) {
        logs = json.get<std::vector<Log>>();
        return true;
    } else {
        SILKRPC_ERROR << "cbor_decode<std::vector<Log>> unexpected json: " << json.dump() << "\n";
        return false;
    }
}

bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Receipt>& receipts) {
    if (bytes.size() == 0) {
        return false;
    }
    auto json = nlohmann::json::from_cbor(bytes);
    SILKRPC_TRACE << "cbor_decode<std::vector<Receipt>> json: " << json.dump() << "\n";
    if (json.is_array()) {
        receipts = json.get<std::vector<Receipt>>();
        return true;
    } else {
        SILKRPC_ERROR << "cbor_decode<std::vector<Receipt>> unexpected json: " << json.dump() << "\n";
        return false;
    }
}

} // namespace silkrpc
