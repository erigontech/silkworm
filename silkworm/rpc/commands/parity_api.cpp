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
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/state/state_reader.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

using db::state::StateReader;

// https://eth.wiki/json-rpc/API#parity_getblockreceipts
Task<void> ParityRpcApi::handle_parity_get_block_receipts(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid parity_getBlockReceipts params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage{tx->create_storage()};

        const auto bnoh = BlockNumberOrHash{block_id};
        const auto block_number = co_await core::get_block_number(bnoh, *tx);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_number.first);
        if (block_with_hash) {
            auto receipts{co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_)};
            SILK_TRACE << "#receipts: " << receipts.size();

            const auto block{block_with_hash->block};
            if (receipts.size() == block.transactions.size()) {
                for (size_t i{0}; i < block.transactions.size(); ++i) {
                    receipts[i].effective_gas_price = block.transactions[i].effective_gas_price(block.header.base_fee_per_gas.value_or(0));
                }
                reply = make_json_content(request, receipts);
            } else {
                reply = make_json_content(request, {});
            }
        } else {
            reply = make_json_content(request, {});
        }
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

void increment(Bytes& array) {
    for (auto it = array.rbegin(); it != array.rend(); ++it) {
        if (*it < 0xFF) {
            (*it)++;
            break;
        } else {
            *it = 0x00;
        }
    }
}

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
    std::string block_id = core::kLatestBlockId;
    if (params.size() >= 4) {
        block_id = params[3].get<std::string>();
    }

    SILK_DEBUG << "address: " << address
               << " quantity: " << quantity
               << " offset: " << (offset ? silkworm::to_hex(offset.value(), true) : "null");

    auto tx = co_await database_->begin();

    try {
        const auto block_number = co_await core::get_block_number(block_id, *tx);
        SILK_DEBUG << "read account with address: " << address << " block number: " << block_number;
        StateReader state_reader{*tx, block_number};
        std::optional<Account> account = co_await state_reader.read_account(address);
        if (!account) throw std::domain_error{"account not found"};

        const auto txn_number = co_await db::txn::min_tx_num(*tx, block_number);
        auto from = db::code_domain_key(address);

        if (offset) {
            from.append(offset.value());
        }
        auto to = db::code_domain_key(address);
        increment(to);
        SILK_DEBUG << "handle_parity_list_storage_keys: from " << from << ", to " << to;

        db::kv::api::DomainRangeQuery query{
                .table = db::table::kStorageDomain,
                .from_key = from,
                .to_key = to,
                .timestamp = txn_number,
                .ascending_order = true,
                .limit = quantity
         };
        auto paginated_result = co_await tx->domain_range(std::move(query));
        auto it = co_await paginated_result.begin();

        std::vector<std::string> keys;
        while (it != paginated_result.end()) {
            const auto key = (*it).first.substr(20);
            keys.push_back(silkworm::to_hex(key, /*with_prefix=*/true));
            co_await ++it;
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
