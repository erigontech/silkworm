/*
   Copyright 2024 The Silkworm Authors

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

#include "version.hpp"

#include <mutex>
#include <string>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/grpc/client/reconnect.hpp>

#include "../tables.hpp"

namespace silkworm::db::state {

static std::once_flag erigon_data_format_flag;

//! Version of Erigon data format for state
static std::string erigon_data_format_version;

//! String key in DbInfo table identifying the Erigon version
constexpr auto kErigonVersionFinished{"ErigonVersionFinished"};

Task<void> set_data_format(kv::api::Client& kv_client) {
    const auto kv_service = kv_client.service();
    bool warning_emitted{false};
    while (true) {
        try {
            const auto tx = co_await kv_service->begin_transaction();
            const auto version_bytes = co_await tx->get_one(table::kDatabaseInfoName, string_to_bytes(kErigonVersionFinished));
            std::call_once(erigon_data_format_flag, [&]() {
                erigon_data_format_version = bytes_to_string(version_bytes);
                SILK_INFO << "Erigon data format version: " << erigon_data_format_version;
            });
            co_await tx->close();
            SILK_TRACE << "Erigon data format: " << (db::state::is_data_format_v3() ? "v3" : "v2");
            break;
        } catch (const boost::system::system_error& se) {
            if (!warning_emitted) {
                SILK_WARN << "Cannot retrieve Erigon data format: " << se.what();
                warning_emitted = true;
            }
        }
        co_await sleep(std::chrono::milliseconds(rpc::kDefaultMinBackoffReconnectTimeout));
    }
}

bool is_data_format_v3() {
    return erigon_data_format_version.starts_with("3");
}

}  // namespace silkworm::db::state
