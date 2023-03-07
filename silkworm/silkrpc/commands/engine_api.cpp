
/*
    Copyright 2022 The Silkrpc Authors

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

#include "engine_api.hpp"

#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>

namespace silkrpc::commands {
using evmc::literals::operator""_bytes32;

// Format for params is a list which includes a payloadId ie. [payloadId]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_getpayloadv1
boost::asio::awaitable<void> EngineRpcApi::handle_engine_get_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request.at("params");

    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV1 params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request.at("id"), 100, error_msg);
        co_return;
    }
    #ifndef BUILD_COVERAGE
    try {
    #endif
        const auto payload_id = params[0].get<std::string>();
        auto payload = co_await backend_->engine_get_payload_v1(std::stoul(payload_id, 0, 16));
        reply = make_json_content(request["id"], payload);
    #ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -38001, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -38001, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -38001, "unexpected exception");
    }
    #endif
}

// Format for params is a JSON object ie [ExecutionPayload]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_newpayloadv1
boost::asio::awaitable<void> EngineRpcApi::handle_engine_new_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request.at("params");

    if (params.size() != 1) {
        auto error_msg = "invalid engine_newPayloadV1 params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request.at("id"), 100, error_msg);
        co_return;
    }
    #ifndef BUILD_COVERAGE
    try {
    #endif
        const auto payload = params[0].get<ExecutionPayload>();
        auto new_payload = co_await backend_->engine_new_payload_v1(payload);
        reply = make_json_content(request["id"], new_payload);
    #ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }
    #endif
}

// Format for params is a JSON list containing two objects
// one ForkChoiceState and one PayloadAttributes, i.e. [ForkChoiceState, PayloadAttributes]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_forkchoiceupdatedv1
boost::asio::awaitable<void> EngineRpcApi::handle_engine_forkchoice_updated_v1(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request.at("params");

    if (params.size() != 1 && params.size() != 2) {
        auto error_msg = "invalid engine_forkchoiceUpdatedV1 params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request.at("id"), 100, error_msg);
        co_return;
    }
    #ifndef BUILD_COVERAGE
    try {
    #endif
        constexpr auto zero_hash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
        const ForkChoiceState forkchoice_state = params[0].get<ForkChoiceState>();

        if (forkchoice_state.safe_block_hash == zero_hash) {
            const auto error_msg = "safe block hash is empty";
            SILKRPC_ERROR << error_msg << "\n";
            reply = make_json_error(request.at("id"), 100, error_msg);
            co_return;
        }

        if (forkchoice_state.finalized_block_hash == zero_hash) {
            const auto error_msg = "finalized block hash is empty";
            SILKRPC_ERROR << error_msg << "\n";
            reply = make_json_error(request.at("id"), 100, error_msg);
            co_return;
        }

        if (params.size() == 2 && !params[1].is_null()) {
            const PayloadAttributes payload_attributes = params[1].get<PayloadAttributes>();
            const ForkChoiceUpdatedRequest forkchoice_update_request{
                .fork_choice_state = forkchoice_state,
                .payload_attributes = std::make_optional(payload_attributes)
            };
            const auto fork_updated = co_await backend_->engine_forkchoice_updated_v1(forkchoice_update_request);
            reply = make_json_content(request["id"], fork_updated);
        } else {
            const ForkChoiceUpdatedRequest forkchoice_update_request{
                .fork_choice_state = forkchoice_state,
                .payload_attributes = std::nullopt
            };
            const auto fork_updated = co_await backend_->engine_forkchoice_updated_v1(forkchoice_update_request);
            reply = make_json_content(request["id"], fork_updated);
        }
    #ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request.at("id"), 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request.at("id"), 100, "unexpected exception");
    }
    #endif
}

// Checks if the transition configurations of the Execution Layer is equal to the ones in the Consensus Layer
// Format for params is a JSON list of TransitionConfiguration, i.e. [TransitionConfiguration]
boost::asio::awaitable<void> EngineRpcApi::handle_engine_exchange_transition_configuration_v1(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_exchangeTransitionConfigurationV1 params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request.at("id"), 100, error_msg);
        co_return;
    }
    const auto cl_configuration = params[0].get<TransitionConfiguration>();
    auto tx = co_await database_->begin();
    #ifndef BUILD_COVERAGE
    try {
    #endif
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILKRPC_DEBUG << "chain config: " << chain_config << "\n";
        auto config = silkworm::ChainConfig::from_json(chain_config.config).value();
        // CL will always pass in 0 as the terminal block number
        if (cl_configuration.terminal_block_number != 0) {
            SILKRPC_ERROR << "consensus layer has the wrong terminal block number expected zero but instead got: "
                << cl_configuration.terminal_block_number << "\n";
            reply = make_json_error(request.at("id"), 100, "consensus layer terminal block number is not zero");
            co_return;
        }
        if (config.terminal_total_difficulty == std::nullopt) {
            SILKRPC_ERROR << "execution layer does not have terminal total difficulty\n";
            reply = make_json_error(request.at("id"), 100, "execution layer does not have terminal total difficulty");
            co_return;
        }
        if (config.terminal_total_difficulty.value() != cl_configuration.terminal_total_difficulty) {
            SILKRPC_ERROR << "execution layer has the incorrect terminal total difficulty, expected: "
                << cl_configuration.terminal_total_difficulty << " got: " << config.terminal_total_difficulty.value() << "\n";
            reply = make_json_error(request.at("id"), 100, "incorrect terminal total difficulty");
            co_return;
        }
        const auto transition_configuration = TransitionConfiguration{
            .terminal_total_difficulty = config.terminal_total_difficulty.value(),
            .terminal_block_hash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32,
            .terminal_block_number = 0 // terminal_block_number removed from chain_config we default to returning zero
        };
        reply = make_json_content(request["id"], transition_configuration);
    #ifndef BUILD_COVERAGE
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request.at("id"), 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request.at("id"), 100, "unexpected exception");
    }
    #endif
    co_await tx->close(); // RAII not (yet) available with coroutines
}
} // namespace silkrpc::commands
