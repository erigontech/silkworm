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

#include "parity_api.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

using db::kv::StateReader;

Task<void> ParityRpcApi::handle_parity_list_storage_keys(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid parity_listStorageKeys params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto quantity = params[1].get<int64_t>();
    std::optional<Bytes> offset = std::nullopt;
    if (params.size() >= 3 && !params[2].is_null()) {
        auto value = params[2].get<std::string>();
        offset = silkworm::from_hex(value);
    }
    std::string block_id = kLatestBlockId;
    if (params.size() >= 4) {
        block_id = params[3].get<std::string>();
    }

    SILK_DEBUG << "address: " << address
               << " quantity: " << quantity
               << " offset: " << (offset ? silkworm::to_hex(offset.value(), true) : "null");

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        SILK_DEBUG << "read account with address: " << address << " block number: " << block_num;

        std::optional<TxnId> txn_number;
        const bool is_latest_block = co_await block_reader.is_latest_block_num(block_num);
        if (!is_latest_block) {
            txn_number = co_await tx->user_txn_id_at(block_num);
        }

        StateReader state_reader{*tx, txn_number};
        std::optional<Account> account = co_await state_reader.read_account(address);
        if (!account) throw std::domain_error{"account not found"};

        auto from = db::code_domain_key(address);

        if (offset) {
            from.append(offset.value());
        }
        auto to = db::code_domain_key(address);
        increment(to);
        SILK_DEBUG << "handle_parity_list_storage_keys: from " << from << ", to " << to;

        db::kv::api::DomainRangeRequest query{
            .table = db::table::kStorageDomain,
            .from_key = from,
            .to_key = to,
            .timestamp = txn_number,
            .ascending_order = true,
            .limit = quantity};
        auto paginated_result = co_await tx->range_as_of(std::move(query));
        auto it = co_await paginated_result.begin();

        std::vector<std::string> keys;
        while (const auto value = co_await it->next()) {
            SILKWORM_ASSERT(value->first.size() >= kAddressLength);
            const auto key = value->first.substr(kAddressLength);
            keys.push_back(silkworm::to_hex(key, /*with_prefix=*/true));
        }
        reply = make_json_content(request, keys);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

}  // namespace silkworm::rpc::commands
