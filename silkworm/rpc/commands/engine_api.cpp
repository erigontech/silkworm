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
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/rpc/json/client_version.hpp>
#include <silkworm/rpc/protocol/errors.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::commands {

using namespace std::chrono_literals;
using namespace concurrency::awaitable_wait_for_one;

// Engine API standard timeouts
static constexpr std::chrono::seconds kGetPayloadTimeout{1s};
static constexpr std::chrono::seconds kGetPayloadBodiesTimeout{10s};
static constexpr std::chrono::seconds kNewPayloadTimeout{8s};
static constexpr std::chrono::seconds kForkChoiceUpdatedTimeout{8s};

static constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

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
        "engine_getClientVersionV1",
        "engine_newPayloadV1",
        "engine_newPayloadV2",
        "engine_newPayloadV3",
        "engine_newPayloadV4",
        "engine_forkchoiceUpdatedV1",
        "engine_forkchoiceUpdatedV2",
        "engine_forkchoiceUpdatedV3",
        "engine_getPayloadV1",
        "engine_getPayloadV2",
        "engine_getPayloadV3",
        "engine_getPayloadV4",
        "engine_getPayloadBodiesByHashV1",
        "engine_getPayloadBodiesByRangeV1",
        "engine_exchangeTransitionConfigurationV1",
    };
    SILK_DEBUG << "RemoteBackEnd::engine_exchange_capabilities execution layer capabilities: " << el_capabilities;
    reply = make_json_content(request, el_capabilities);
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/identification.md#ClientVersionV1
Task<void> EngineRpcApi::handle_engine_get_client_version_v1(const nlohmann::json& request, std::string& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getClientVersionV1 params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    make_glaze_json_content(request, build_info_, reply);
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
        const auto payload_and_value = co_await engine_->get_payload(from_quantity(payload_quantity), kGetPayloadTimeout);
        reply = make_json_content(request, payload_and_value.payload);
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
        const auto payload_and_value = co_await engine_->get_payload(from_quantity(payload_quantity), kGetPayloadTimeout);
        reply = make_json_content(request, payload_and_value);
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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_getpayloadv3
Task<void> EngineRpcApi::handle_engine_get_payload_v3(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV3 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto payload_quantity = params[0].get<std::string>();
        // TODO(canepat) we need a way to specify V3 i.e. blobs should be returned (hint: use versioned struct PayloadIdentifier)
        const auto payload_and_value = co_await engine_->get_payload(from_quantity(payload_quantity), kGetPayloadTimeout);
        reply = make_json_content(request, payload_and_value);
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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_getpayloadv4
Task<void> EngineRpcApi::handle_engine_get_payload_v4(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto& params = request.at("params");
    if (params.size() != 1) {
        auto error_msg = "invalid engine_getPayloadV4 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto payload_quantity = params[0].get<std::string>();
        const auto payload_and_value = co_await engine_->get_payload(from_quantity(payload_quantity), kGetPayloadTimeout);
        reply = make_json_content(request, payload_and_value);
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
        const auto payload_bodies = co_await engine_->get_payload_bodies_by_hash(block_hashes, kGetPayloadBodiesTimeout);
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
            co_return;
        }
        // We MUST support count values of at least 32 and MUST check if number is too large for us [Specification 2.]
        if (count > 32) {
            const auto error_msg = "count value > 32 is too large";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kTooLargeRequest, error_msg);
            co_return;
        }
        const auto payload_bodies = co_await engine_->get_payload_bodies_by_range(start, count, kGetPayloadBodiesTimeout);
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
        auto payload = params[0].get<ExecutionPayload>();
        NewPayloadRequest new_payload_v1_request{.execution_payload = std::move(payload)};
        const auto new_payload = co_await engine_->new_payload(new_payload_v1_request, kNewPayloadTimeout);
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
    auto payload = params[0].get<ExecutionPayload>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto storage{tx->create_storage()};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");

        // We MUST check that CL has sent the expected ExecutionPayload version [Specification for params]
        if (payload.timestamp < config.shanghai_time && payload.version != ExecutionPayload::kV1) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV1 if timestamp lower than Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }
        if (payload.timestamp >= config.shanghai_time && payload.version != ExecutionPayload::kV2) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV2 if timestamp greater or equal to Shanghai";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kInvalidParams, error_msg);
            co_await tx->close();
            co_return;
        }
        if (config.cancun_time && payload.timestamp >= config.cancun_time) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV3 if timestamp greater or equal to Cancun";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kUnsupportedFork, error_msg);
            co_await tx->close();
            co_return;
        }

        NewPayloadRequest new_payload_v2_request{.execution_payload = std::move(payload)};
        const auto new_payload = co_await engine_->new_payload(new_payload_v2_request, kNewPayloadTimeout);

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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_newpayloadv3
Task<void> EngineRpcApi::handle_engine_new_payload_v3(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 3) {
        auto error_msg = "invalid engine_newPayloadV3 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto payload = params[0].get<ExecutionPayload>();
    auto expected_blob_versioned_hashes = params[1].get<std::vector<Hash>>();
    auto parent_beacon_block_root = params[2].get<evmc::bytes32>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto storage{tx->create_storage()};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");
        ensure(config.cancun_time.has_value(), "execution layer has no Cancun timestamp in configuration");

        // We MUST check that CL has sent the expected ExecutionPayload version [Specification for params]
        if (payload.timestamp >= config.cancun_time && payload.version != ExecutionPayload::kV3) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV3 if timestamp greater or equal to Cancun";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kUnsupportedFork, error_msg);
            co_await tx->close();
            co_return;
        }

        NewPayloadRequest new_payload_v3_request{
            .execution_payload = std::move(payload),
            .expected_blob_versioned_hashes = std::move(expected_blob_versioned_hashes),
            .parent_beacon_block_root = parent_beacon_block_root,
        };
        // TODO(canepat) get rid of first timeout?
        const auto status_var = co_await (engine_->new_payload(new_payload_v3_request, kNewPayloadTimeout) ||
                                          concurrency::timeout(kNewPayloadTimeout));
        ensure(std::holds_alternative<rpc::PayloadStatus>(status_var), "engine_newPayloadV3: unexpected awaitable operators outcome");
        const auto payload_status = std::get<rpc::PayloadStatus>(status_var);
        reply = make_json_content(request, payload_status);
#ifndef BUILD_COVERAGE
    } catch (const concurrency::TimeoutExpiredError& tee) {
        SILK_WARN << "engine_newPayloadV3: timeout expired: " << tee.what();
        reply = make_json_content(request, rpc::PayloadStatus::kSyncing);
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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/prague.md#engine_newpayloadv4
Task<void> EngineRpcApi::handle_engine_new_payload_v4(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 3) {
        auto error_msg = "invalid engine_newPayloadV4 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto payload = params[0].get<ExecutionPayload>();
    auto expected_blob_versioned_hashes = params[1].get<std::vector<Hash>>();
    auto parent_beacon_block_root = params[2].get<evmc::bytes32>();
    auto execution_requests = params[3].get<std::vector<Bytes>>();
    auto tx = co_await database_->begin();

#ifndef BUILD_COVERAGE
    try {
#endif
        const auto storage{tx->create_storage()};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");
        ensure(config.cancun_time.has_value(), "execution layer has no Cancun timestamp in configuration");
        ensure(config.prague_time.has_value(), "execution layer has no Prague timestamp in configuration");

        // We MUST check that CL has sent the expected ExecutionPayload version [Specification for params]
        if (payload.timestamp < config.prague_time) {
            const auto error_msg = "consensus layer must use ExecutionPayloadV4 if timestamp greater or equal to Prague";
            SILK_ERROR << error_msg;
            reply = make_json_error(request, kUnsupportedFork, error_msg);
            co_await tx->close();
            co_return;
        }

        NewPayloadRequest new_payload_v4_request{
            .execution_payload = std::move(payload),
            .expected_blob_versioned_hashes = std::move(expected_blob_versioned_hashes),
            .parent_beacon_block_root = parent_beacon_block_root,
            .execution_requests = execution_requests};
        const auto new_payload = co_await engine_->new_payload(new_payload_v4_request, kNewPayloadTimeout);

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

        // We MUST check that ForkChoiceState is valid and consistent [Paris Specification 8.]
        if (const auto res{validate_fork_choice_state_v1(fork_choice_state)}; !res) {
            const auto [error_code, error_msg] = res.error();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, error_code, error_msg);
            co_return;
        }

        std::optional<PayloadAttributes> payload_attributes;
        if (params.size() == 2 && !params[1].is_null()) {
            payload_attributes = params[1].get<PayloadAttributes>();
        }
        const ForkChoiceUpdatedRequest fcu_request{fork_choice_state, payload_attributes};
        const auto fcu_reply = co_await engine_->fork_choice_updated(fcu_request, kForkChoiceUpdatedTimeout);

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

        // We MUST check that ForkChoiceState is valid and consistent [Paris Specification 8.]
        if (const auto res{validate_fork_choice_state_v1(fork_choice_state)}; !res) {
            const auto [error_code, error_msg] = res.error();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, error_code, error_msg);
            co_return;
        }

        std::optional<PayloadAttributes> payload_attributes;
        if (params.size() == 2 && !params[1].is_null()) {
            payload_attributes = params[1].get<PayloadAttributes>();
        }
        const ForkChoiceUpdatedRequest fcu_request{fork_choice_state, payload_attributes};
        const auto fcu_reply = co_await engine_->fork_choice_updated(fcu_request, kForkChoiceUpdatedTimeout);

        // We MUST check that CL has sent consistent PayloadAttributes [Shanghai Specification 2.]
        const auto chain_config{co_await read_chain_config()};
        if (const auto res{validate_payload_attributes_v2(payload_attributes, fcu_reply, chain_config)}; !res) {
            const auto [error_code, error_msg] = res.error();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, error_code, error_msg);
            co_return;
        }

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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#engine_forkchoiceupdatedv3
Task<void> EngineRpcApi::handle_engine_forkchoice_updated_v3(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request.at("params");
    if (params.size() != 1 && params.size() != 2) {
        auto error_msg = "invalid engine_forkchoiceUpdatedV3 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto fork_choice_state = params[0].get<ForkChoiceState>();

        // We MUST check that ForkChoiceState is valid and consistent [Paris Specification 8.]
        if (const auto res{validate_fork_choice_state_v1(fork_choice_state)}; !res) {
            const auto [error_code, error_msg] = res.error();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, error_code, error_msg);
            co_return;
        }

        std::optional<PayloadAttributes> payload_attributes;
        if (params.size() == 2 && !params[1].is_null()) {
            payload_attributes = params[1].get<PayloadAttributes>();
        }
        const ForkChoiceUpdatedRequest fcu_request{fork_choice_state, payload_attributes};
        const auto fcu_reply = co_await engine_->fork_choice_updated(fcu_request, kForkChoiceUpdatedTimeout);

        // We MUST check that CL has sent consistent PayloadAttributes [Cancun Specification 2.]
        const auto chain_config{co_await read_chain_config()};
        if (auto res{validate_payload_attributes_v3(payload_attributes, fcu_reply, chain_config)}; !res) {
            const auto [error_code, error_msg] = res.error();
            reply = make_json_error(request, error_code, error_msg);
            co_return;
        }

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
        const auto storage{tx->create_storage()};
        const auto config{co_await storage->read_chain_config()};
        ensure(config.terminal_total_difficulty.has_value(), "execution layer does not have terminal total difficulty");

        // We SHOULD check for any configuration mismatch except `terminalBlockNumber` [Specification 2.]
        if (config.terminal_total_difficulty != cl_configuration.terminal_total_difficulty) {
            SILK_ERROR << "execution layer has the incorrect terminal total difficulty, expected: "
                       << cl_configuration.terminal_total_difficulty << " got: " << config.terminal_total_difficulty.value();
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
            .terminal_total_difficulty = config.terminal_total_difficulty.value(),
            .terminal_block_hash = kZeroHash,  // terminal_block_hash removed from chain_config, return zero
            .terminal_block_num = 0            // terminal_block_num removed from chain_config, return zero
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

// https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#forkchoicestatev1
EngineRpcApi::ValidationError EngineRpcApi::validate_fork_choice_state_v1(const ForkChoiceState& state) {
    // safeBlockHash and finalizedBlockHash are not allowed to be zero because transition block is finalized
    if (state.safe_block_hash == kZeroHash) {
        return tl::make_unexpected<ApiError>({kInvalidForkChoiceState, "safe block hash is empty"});
    }
    if (state.finalized_block_hash == kZeroHash) {
        return tl::make_unexpected<ApiError>({kInvalidForkChoiceState, "finalized block hash is empty"});
    }
    return {};
}

// https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_forkchoiceupdatedv2
EngineRpcApi::ValidationError EngineRpcApi::validate_payload_attributes_v2(const std::optional<PayloadAttributes>& attributes,
                                                                           const ForkChoiceUpdatedReply& reply,
                                                                           const std::optional<silkworm::ChainConfig>& config) {
    // Payload attributes must be validated only if non-null and FCU is valid
    if (!attributes || reply.payload_status.status != PayloadStatus::kValidStr) {
        return {};
    }

    ensure(config.has_value(), "execution layer has invalid configuration");
    ensure(config->shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");

    if (attributes->timestamp < config->shanghai_time && attributes->version != PayloadAttributes::kV1) {
        return tl::make_unexpected<ApiError>(
            {kInvalidParams, "consensus layer must use PayloadAttributesV1 if timestamp lower than Shanghai"});
    }
    if (attributes->timestamp >= config->shanghai_time && attributes->version != PayloadAttributes::kV2) {
        return tl::make_unexpected<ApiError>(
            {kInvalidParams, "consensus layer must use PayloadAttributesV2 if timestamp greater or equal to Shanghai"});
    }
    if (attributes->timestamp >= config->cancun_time) {
        return tl::make_unexpected<ApiError>(
            {kUnsupportedFork, "consensus layer must use PayloadAttributesV3 if timestamp greater or equal to Cancun"});
    }
    return {};
}

EngineRpcApi::ValidationError EngineRpcApi::validate_payload_attributes_v3(const std::optional<PayloadAttributes>& attributes,
                                                                           const ForkChoiceUpdatedReply& reply,
                                                                           const std::optional<silkworm::ChainConfig>& config) {
    // Payload attributes must be validated only if non-null and FCU is valid
    if (!attributes || reply.payload_status.status != PayloadStatus::kValidStr) {
        return {};
    }

    ensure(config.has_value(), "execution layer has invalid configuration");
    ensure(config->shanghai_time.has_value(), "execution layer has no Shanghai timestamp in configuration");
    ensure(config->cancun_time.has_value(), "execution layer has no Cancun timestamp in configuration");

    if (attributes->timestamp < config->cancun_time) {
        return tl::make_unexpected<ApiError>(
            {kUnsupportedFork, "consensus layer must not use PayloadAttributesV3 if timestamp lower than Cancun"});
    }
    if (attributes->timestamp >= config->cancun_time && attributes->version != PayloadAttributes::kV3) {
        return tl::make_unexpected<ApiError>(
            {kInvalidPayloadAttributes, "consensus layer must use PayloadAttributesV3 if timestamp greater or equal to Cancun"});
    }
    return {};
}

Task<std::optional<silkworm::ChainConfig>> EngineRpcApi::read_chain_config() {
    auto tx = co_await database_->begin();
    const auto storage{tx->create_storage()};
    auto config{co_await storage->read_chain_config()};
    co_await tx->close();
    co_return config;
}

}  // namespace silkworm::rpc::commands
