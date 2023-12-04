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

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/protocol/errors.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::commands {

using evmc::literals::operator""_bytes32;

constexpr auto kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

// https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#engine_exchangecapabilities
Task<void> EngineRpcApi::handle_engine_exchange_capabilities(  // NOLINT(readability-convert-member-functions-to-static)
    const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_exchangeCapabilities params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto cl_capabilities = params[0].get<Capabilities>();
    SILK_DEBUG << "RemoteBackEnd::engine_exchange_capabilities consensus layer capabilities: " << cl_capabilities;
    const Capabilities el_capabilities{
        "engine_newPayloadV1",
        "engine_newPayloadV2",
        "engine_forkchoiceUpdatedV1",
        "engine_forkchoiceUpdatedV2",
        "engine_getPayloadV1",
        "engine_getPayloadV2",
        "engine_getPayloadBodiesByHashV1",
        "engine_getPayloadBodiesByRangeV1",
        "engine_exchangeTransitionConfigurationV1",
    };
    SILK_DEBUG << "RemoteBackEnd::engine_exchange_capabilities execution layer capabilities: " << el_capabilities;
    reply = make_json_content(request, el_capabilities);
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_getpayloadv1
Task<void> EngineRpcApi::handle_engine_get_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto payload_quantity = params[0].get<std::string>();
        const auto payload_and_value = co_await backend_->engine_get_payload(from_quantity(payload_quantity));
        reply = make_json_content(request, payload_and_value.payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        // TODO(canepat) the error code should be se.code().value() here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        // TODO(canepat) the error code should be kInternalError here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        // TODO(canepat) the error code should be kServerError here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, "unexpected exception");
    }
#endif
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_getpayloadv2
Task<void> EngineRpcApi::handle_engine_get_payload_v2(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV2 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto payload_quantity = params[0].get<std::string>();
        const auto payload_and_value = co_await backend_->engine_get_payload(from_quantity(payload_quantity));
        reply = make_json_content(request, payload_and_value);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        // TODO(canepat) the error code should be se.code().value() here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        // TODO(canepat) the error code should be kInternalError here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        // TODO(canepat) the error code should be kServerError here: application-level errors should come from BackEnd
        reply = make_json_error(request, kUnknownPayload, "unexpected exception");
    }
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_getpayloadbodiesbyhashv1
Task<void> EngineRpcApi::handle_engine_get_payload_bodies_by_hash_v1(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadBodiesByHashV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto block_hashes = params[0].get<std::vector<Hash>>();
        // We MUST support at least 32 block hashes and MUST check if number is too large for us [Specification 3.]
        if (block_hashes.size() > 32) {
            const auto error_msg = "number of block hashes > 32 is too large";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kTooLargeRequest, error_msg);
        }
        const auto payload_bodies = co_await backend_->engine_get_payload_bodies_by_hash(block_hashes);
        reply = make_json_content(request, payload_bodies);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_getpayloadbodiesbyrangev1
Task<void> EngineRpcApi::handle_engine_get_payload_bodies_by_range_v1(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto& params = request.at("params");
    if (params.size() != 2) {
        auto error_msg = "invalid engine_getPayloadBodiesByRangeV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto start = from_quantity(params[0].get<std::string>());
        const auto count = from_quantity(params[1].get<std::string>());
        if (count == 0) {
            const auto error_msg = "count 0 is invalid";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidParams, error_msg);
        }
        // We MUST support count values of at least 32 and MUST check if number is too large for us [Specification 2.]
        if (count > 32) {
            const auto error_msg = "count value > 32 is too large";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kTooLargeRequest, error_msg);
        }
        const auto payload_bodies = co_await backend_->engine_get_payload_bodies_by_range(start, count);
        reply = make_json_content(request, payload_bodies);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_newpayloadv1
Task<void> EngineRpcApi::handle_engine_new_payload_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_newPayloadV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto payload = params[0].get<ExecutionPayload>();
        auto new_payload = co_await backend_->engine_new_payload(payload);
        reply = make_json_content(request, new_payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
#endif
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_newpayloadv2
Task<void> EngineRpcApi::handle_engine_new_payload_v2(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_newPayloadV2 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto payload = params[0].get<ExecutionPayload>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        ethdb::TransactionDatabase tx_database{*tx};
        const auto storage{tx->create_storage(tx_database, backend_)};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.has_value(), "execution layer has invalid configuration");
        ensure(config->shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");

        // We MUST check that CL has sent the expected ExecutionPayload version [Specification for params]
        if (payload.timestamp < config->shanghai_time and payload.version != ExecutionPayload::V1) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV1 if timestamp lower than Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }
        if (payload.timestamp >= config->shanghai_time and payload.version != ExecutionPayload::V2) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV2 if timestamp greater or equal to Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }

        const auto new_payload = co_await backend_->engine_new_payload(payload);

        reply = make_json_content(request, new_payload);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
#endif
    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_forkchoiceupdatedv1
Task<void> EngineRpcApi::handle_engine_forkchoice_updated_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1 && params.size() != 2) {
        auto error_msg = "invalid engine_forkchoiceUpdatedV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto fork_choice_state = params[0].get<ForkChoiceState>();
        // We MUST check that ForkChoiceState is valid and consistent [Specification 9.]
        if (fork_choice_state.safe_block_hash == kZeroHash) {
            const auto error_msg = "safe block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidForkChoiceState, error_msg);
            co_return;
        }
        if (fork_choice_state.finalized_block_hash == kZeroHash) {
            const auto error_msg = "finalized block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidForkChoiceState, error_msg);
            co_return;
        }

        std::optional<PayloadAttributes> payload_attributes;
        if (params.size() == 2 && !params[1].is_null()) {
            payload_attributes = params[1].get<PayloadAttributes>();
        }
        const ForkChoiceUpdatedRequest fcu_request{fork_choice_state, payload_attributes};
        const auto fcu_reply = co_await backend_->engine_forkchoice_updated(fcu_request);
        reply = make_json_content(request, fcu_reply);
#ifndef BUILD_COVERAGE
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
#endif
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_forkchoiceupdatedv2
Task<void> EngineRpcApi::handle_engine_forkchoice_updated_v2(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1 && params.size() != 2) {
        auto error_msg = "invalid engine_forkchoiceUpdatedV2 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto fork_choice_state = params[0].get<ForkChoiceState>();
        // We MUST check that ForkChoiceState is valid and consistent [Specification 9.]
        if (fork_choice_state.safe_block_hash == kZeroHash) {
            const auto error_msg = "safe block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidForkChoiceState, error_msg);
            co_return;
        }
        if (fork_choice_state.finalized_block_hash == kZeroHash) {
            const auto error_msg = "finalized block hash is empty";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidForkChoiceState, error_msg);
            co_return;
        }

        std::optional<PayloadAttributes> payload_attributes;
        if (params.size() == 2 && !params[1].is_null()) {
            const auto attributes = params[1].get<PayloadAttributes>();

            auto tx = co_await database_->begin();
            ethdb::TransactionDatabase tx_database{*tx};
            const auto storage{tx->create_storage(tx_database, backend_)};
            const auto config{co_await storage->read_chain_config()};
            co_await tx->close();
            ensure(config.has_value(), "execution layer has invalid configuration");
            ensure(config->shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");

            // We MUST check that CL has sent the expected PayloadAttributes version [Specification for params]
            if (attributes.timestamp < config->shanghai_time and attributes.version != PayloadAttributes::V1) {
                const auto error_msg = "consensus layer must use PayloadAttributesV1 if timestamp lower than Shanghai";
                SILK_ERROR << error_msg;
                reply = make_json_error(request, kInvalidParams, error_msg);
                co_return;
            }
            if (attributes.timestamp >= config->shanghai_time and attributes.version != PayloadAttributes::V2) {
                const auto error_msg = "consensus layer must use PayloadAttributesV2 if timestamp greater or equal to Shanghai";
                SILK_ERROR << error_msg;
                reply = make_json_error(request, kInvalidParams, error_msg);
                co_return;
            }
            payload_attributes = attributes;
        }
        const ForkChoiceUpdatedRequest fcu_request{fork_choice_state, payload_attributes};
        const auto fcu_reply = co_await backend_->engine_forkchoice_updated(fcu_request);
        reply = make_json_content(request, fcu_reply);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, se.code().value(), se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// Checks if the transition configurations of the Execution Layer is equal to the ones in the Consensus Layer
// Format for params is a JSON list of TransitionConfiguration, i.e. [TransitionConfiguration]
// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#TransitionConfigurationV1
Task<void> EngineRpcApi::handle_engine_exchange_transition_configuration_v1(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_exchangeTransitionConfigurationV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto cl_configuration = params[0].get<TransitionConfiguration>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        ethdb::TransactionDatabase tx_database{*tx};
        const auto storage{tx->create_storage(tx_database, backend_)};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.has_value(), "execution layer has invalid configuration");
        ensure(config->terminal_total_difficulty.has_value(), "execution layer does not have terminal total difficulty");

        // We SHOULD check for any configuration mismatch except `terminalBlockNumber` [Specification 2.]
        if (config->terminal_total_difficulty != cl_configuration.terminal_total_difficulty) {
            SILK_ERROR << "execution layer has the incorrect terminal total difficulty, expected: "
                       << cl_configuration.terminal_total_difficulty << " got: " << config->terminal_total_difficulty.value();
            reply = make_json_error(request, kInvalidParams, "consensus layer terminal total difficulty does not match");
            co_await tx->close();
            co_return;
        }
        if (cl_configuration.terminal_block_hash != kZeroHash) {
            SILK_ERROR << "execution layer has the incorrect terminal block hash, expected: "
                       << silkworm::to_hex(cl_configuration.terminal_block_hash) << " got: " << silkworm::to_hex(kZeroHash);
            reply = make_json_error(request, kInvalidParams, "consensus layer terminal block hash is not zero");
            co_await tx->close();
            co_return;
        }

        // We MUST respond with configurable setting values set according to EIP-3675 [Specification 1.]
        const TransitionConfiguration transition_configuration{
            .terminal_total_difficulty = config->terminal_total_difficulty.value(),
            .terminal_block_hash = kZeroHash,  // terminal_block_hash removed from chain_config, return zero
            .terminal_block_number = 0         // terminal_block_number removed from chain_config, return zero
        };
        reply = make_json_content(request, transition_configuration);
#ifndef BUILD_COVERAGE
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
#endif
    co_await tx->close();  // RAII not (yet) available with coroutines
}

}  // namespace silkworm::rpc::commands
