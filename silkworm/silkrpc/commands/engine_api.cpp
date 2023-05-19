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

#include "engine_api.hpp"

#include <string>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/protocol/errors.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>

namespace silkworm::rpc::commands {

using evmc::literals::operator""_bytes32;

constexpr auto kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

// https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#engine_exchangecapabilities
awaitable<void> EngineRpcApi::handle_engine_exchange_capabilities(  // NOLINT(readability-convert-member-functions-to-static)
    const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_exchangeCapabilities params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }

    const auto cl_capabilities = params[0].get<Capabilities>();
    SILK_DEBUG << "RemoteBackEnd::engine_exchange_capabilities consensus layer capabilities: " << cl_capabilities;
    const Capabilities el_capabilities{
        "engine_newPayloadV1",
        "engine_forkchoiceUpdatedV1",
        "engine_getPayloadV1",
        "engine_exchangeTransitionConfigurationV1",
    };
    SILK_DEBUG << "RemoteBackEnd::engine_exchange_capabilities execution layer capabilities: " << el_capabilities;
    reply = make_json_content(request["id"], el_capabilities);
}

// Format for params is a list which includes a payloadId ie. [payloadId]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_getpayloadv1
awaitable<void> EngineRpcApi::handle_engine_get_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto payload_id = params[0].get<std::string>();
        const auto payload = co_await backend_->engine_get_payload(std::stoul(payload_id, nullptr, 16));
        reply = make_json_content(request["id"], payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        // TODO(canepat) the error code should be se.code().value() here: application-level errors should come from BackEnd
        reply = make_json_error(request["id"], kUnknownPayload, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        // TODO(canepat) the error code should be kInternalError here: application-level errors should come from BackEnd
        reply = make_json_error(request["id"], kUnknownPayload, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        // TODO(canepat) the error code should be kServerError here: application-level errors should come from BackEnd
        reply = make_json_error(request["id"], kUnknownPayload, "unexpected exception");
    }
#endif
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_newpayloadv1
awaitable<void> EngineRpcApi::handle_engine_new_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_newPayloadV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto payload = params[0].get<ExecutionPayload>();
        auto new_payload = co_await backend_->engine_new_payload(payload);
        reply = make_json_content(request["id"], new_payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request["id"], se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], kServerError, "unexpected exception");
    }
#endif
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_newpayloadv2
awaitable<void> EngineRpcApi::handle_engine_new_payload_v2(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_newPayloadV2 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }
    const auto payload = params[0].get<ExecutionPayload>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        const auto config = silkworm::ChainConfig::from_json(chain_config.config);

        ensure(config.has_value(), "execution layer has invalid configuration");
        ensure(config->shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");

        // We MUST check that CL has sent the expected ExecutionPayload version [Specification for params]
        if (payload.timestamp < config->shanghai_time and payload.version != ExecutionPayload::V1) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV1 if timestamp lower than Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }
        if (payload.timestamp >= config->shanghai_time and payload.version != ExecutionPayload::V2) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV2 if timestamp greater or equal to Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }

        const auto new_payload = co_await backend_->engine_new_payload(payload);

        reply = make_json_content(request["id"], new_payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request["id"], se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], kServerError, "unexpected exception");
    }
#endif
    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_forkchoiceupdatedv1
awaitable<void> EngineRpcApi::handle_engine_forkchoice_updated_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1 && params.size() != 2) {
        auto error_msg = "invalid engine_forkchoiceUpdatedV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto forkchoice_state = params[0].get<ForkChoiceState>();

        if (forkchoice_state.safe_block_hash == kZeroHash) {
            const auto error_msg = "safe block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request.at("id"), kInvalidForChoiceState, error_msg);
            co_return;
        }

        if (forkchoice_state.finalized_block_hash == kZeroHash) {
            const auto error_msg = "finalized block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request.at("id"), kInvalidForChoiceState, error_msg);
            co_return;
        }

        if (params.size() == 2 && !params[1].is_null()) {
            const auto payload_attributes = params[1].get<PayloadAttributes>();
            const ForkChoiceUpdatedRequest forkchoice_update_request{
                .fork_choice_state = forkchoice_state,
                .payload_attributes = std::make_optional(payload_attributes)};
            const auto fork_updated = co_await backend_->engine_forkchoice_updated(forkchoice_update_request);
            reply = make_json_content(request["id"], fork_updated);
        } else {
            const ForkChoiceUpdatedRequest forkchoice_update_request{
                .fork_choice_state = forkchoice_state,
                .payload_attributes = std::nullopt};
            const auto fork_updated = co_await backend_->engine_forkchoice_updated(forkchoice_update_request);
            reply = make_json_content(request["id"], fork_updated);
        }
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request["id"], se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request.at("id"), kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request.at("id"), kServerError, "unexpected exception");
    }
#endif
}

// Checks if the transition configurations of the Execution Layer is equal to the ones in the Consensus Layer
// Format for params is a JSON list of TransitionConfiguration, i.e. [TransitionConfiguration]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#TransitionConfigurationV1
awaitable<void> EngineRpcApi::handle_engine_exchange_transition_configuration_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_exchangeTransitionConfigurationV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request.at("id"), kInvalidParams, error_msg);
        co_return;
    }
    const auto cl_configuration = params[0].get<TransitionConfiguration>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILK_DEBUG << "chain config: " << chain_config;
        const auto config = silkworm::ChainConfig::from_json(chain_config.config);
        ensure(config.has_value(), "execution layer has invalid configuration");
        ensure(config->terminal_total_difficulty.has_value(), "execution layer does not have terminal total difficulty");

        // We SHOULD check for any configuration mismatch except `terminalBlockNumber` [Specification 2.]
        if (config->terminal_total_difficulty != cl_configuration.terminal_total_difficulty) {
            SILK_ERROR << "execution layer has the incorrect terminal total difficulty, expected: "
                       << cl_configuration.terminal_total_difficulty << " got: " << config->terminal_total_difficulty.value();
            reply = make_json_error(request.at("id"), kInvalidParams, "consensus layer terminal total difficulty does not match");
            co_await tx->close();
            co_return;
        }
        if (cl_configuration.terminal_block_hash != kZeroHash) {
            SILK_ERROR << "execution layer has the incorrect terminal block hash, expected: "
                       << cl_configuration.terminal_block_hash << " got: " << kZeroHash;
            reply = make_json_error(request.at("id"), kInvalidParams, "consensus layer terminal block hash is not zero");
            co_await tx->close();
            co_return;
        }

        // We MUST respond with configurable setting values set according to EIP-3675 [Specification 1.]
        const TransitionConfiguration transition_configuration{
            .terminal_total_difficulty = config->terminal_total_difficulty.value(),
            .terminal_block_hash = kZeroHash,  // terminal_block_hash removed from chain_config, return zero
            .terminal_block_number = 0         // terminal_block_number removed from chain_config, return zero
        };
        reply = make_json_content(request["id"], transition_configuration);
#ifndef BUILD_COVERAGE
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request.at("id"), kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request.at("id"), kServerError, "unexpected exception");
    }
#endif
    co_await tx->close();  // RAII not (yet) available with coroutines
}

}  // namespace silkworm::rpc::commands
