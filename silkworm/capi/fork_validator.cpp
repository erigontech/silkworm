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

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/environment.hpp>

#include "common.hpp"
#include "instance.hpp"
#include "silkworm.h"

static void set_node_settings(SilkwormHandle handle, const struct SilkwormForkValidatorSettings& settings, MDBX_env* mdbx_env) {
    silkworm::db::EnvUnmanaged unmanaged_env{mdbx_env};

    auto txn = silkworm::db::ROTxnManaged{unmanaged_env};
    auto chain_config{silkworm::db::read_chain_config(txn)};
    auto prune_mode{silkworm::db::read_prune_mode(txn)};
    txn.abort();
    SILKWORM_ASSERT(chain_config);

    auto data_dir = std::make_unique<silkworm::DataDirectory>(handle->data_dir_path);
    handle->node_settings.data_directory = std::move(data_dir);

    auto db_env_flags = unmanaged_env.get_flags();
    handle->node_settings.chaindata_env_config = silkworm::db::EnvConfig{
        .path = handle->data_dir_path,
        .create = false,
        .readonly = db_env_flags & MDBX_RDONLY ? true : false,
        .exclusive = db_env_flags & MDBX_EXCLUSIVE ? true : false,
        .in_memory = db_env_flags & MDBX_NOMETASYNC ? true : false,
        .shared = db_env_flags & MDBX_ACCEDE ? true : false,
        .read_ahead = db_env_flags & MDBX_NORDAHEAD ? false : true,
        .write_map = db_env_flags & MDBX_WRITEMAP ? true : false,
        .page_size = unmanaged_env.get_pagesize(),
        .max_size = unmanaged_env.dbsize_max(),
        //.growth_size = ?
        .max_tables = unmanaged_env.max_maps(),
        .max_readers = unmanaged_env.max_readers(),
    };

    handle->node_settings.build_info = silkworm::make_application_info(silkworm_get_buildinfo());
    handle->node_settings.network_id = chain_config->chain_id;
    handle->node_settings.chain_config = chain_config;
    handle->node_settings.prune_mode = prune_mode;

    if (settings.batch_size) {
        handle->node_settings.batch_size = settings.batch_size;
    }

    if (settings.etl_buffer_size) {
        handle->node_settings.etl_buffer_size = settings.etl_buffer_size;
    }

    if (settings.sync_loop_throttle_seconds) {
        handle->node_settings.sync_loop_throttle_seconds = settings.sync_loop_throttle_seconds;
    }

    handle->node_settings.parallel_fork_tracking_enabled = false;  // Do not use parallel forks for FCU, not compatible with Erigon?
    handle->node_settings.keep_db_txn_open = false;                // Ensure that the transaction is closed after each request, Erigon manages transactions differently
}

SILKWORM_EXPORT int silkworm_start_fork_validator(SilkwormHandle handle, MDBX_env* mdbx_env, const struct SilkwormForkValidatorSettings* settings) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (handle->execution_engine) {
        return SILKWORM_SERVICE_ALREADY_STARTED;
    }
    if (!mdbx_env) {
        return SILKWORM_INVALID_MDBX_ENV;
    }
    if (!settings) {
        return SILKWORM_INVALID_SETTINGS;
    }

    if (settings->stop_before_senders_stage) {
        silkworm::Environment::set_stop_before_stage(silkworm::db::stages::kSendersKey);
    }

    silkworm::log::Info("Starting fork validator");
    set_node_settings(handle, *settings, mdbx_env);

    silkworm::log::Info("Settings done");

    silkworm::db::EnvUnmanaged unmanaged_env{mdbx_env};
    silkworm::db::RWAccess rw_access{unmanaged_env};
    handle->execution_engine = std::make_unique<silkworm::stagedsync::ExecutionEngine>(handle->node_settings.asio_context, handle->node_settings, rw_access);

    silkworm::log::Info("Execution engine created");

    handle->execution_engine->open();

    silkworm::log::Info("Execution engine opened");

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_stop_fork_validator(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (handle->execution_engine) {
        handle->execution_engine->stop();
        return SILKWORM_OK;
    }
    return SILKWORM_INTERNAL_ERROR;
}

SILKWORM_EXPORT int silkworm_fork_validator_verify_chain(SilkwormHandle handle, bytes_32 head_hash_bytes, struct SilkwormForkValidatorValidationResult* result) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->execution_engine) {
        return SILKWORM_INTERNAL_ERROR;
    }

    silkworm::Hash head_hash{};
    memcpy(head_hash.bytes, head_hash_bytes.bytes, sizeof(head_hash.bytes));

    SILK_INFO << "[Silkworm Fork Validator] Starting Verify Chain for " << to_hex(head_hash);
    try {
        auto execution_result = handle->execution_engine->verify_chain_no_fork_tracking(head_hash);

        if (std::holds_alternative<silkworm::stagedsync::ValidChain>(execution_result)) {
            result->execution_status = SILKWORM_FORK_VALIDATOR_RESULT_STATUS_SUCCESS;
            memcpy(result->last_valid_hash.bytes, std::get<silkworm::stagedsync::ValidChain>(execution_result).current_head.hash.bytes, sizeof(result->last_valid_hash.bytes));
        }

        if (std::holds_alternative<silkworm::stagedsync::InvalidChain>(execution_result)) {
            result->execution_status = SILKWORM_FORK_VALIDATOR_RESULT_STATUS_INVALID;
            auto invalid_chain = std::get<silkworm::stagedsync::InvalidChain>(execution_result);
            memcpy(result->last_valid_hash.bytes, invalid_chain.unwind_point.hash.bytes, sizeof(result->last_valid_hash.bytes));

            if (invalid_chain.bad_block) {
                result->execution_status = SILKWORM_FORK_VALIDATOR_RESULT_STATUS_BAD_BLOCK;
            }
        }

        if (std::holds_alternative<silkworm::stagedsync::ValidationError>(execution_result)) {
            result->execution_status = SILKWORM_FORK_VALIDATOR_RESULT_STATUS_INVALID;
            auto validation_error = std::get<silkworm::stagedsync::ValidationError>(execution_result);
            memcpy(result->last_valid_hash.bytes, validation_error.latest_valid_head.hash.bytes, sizeof(result->last_valid_hash.bytes));
            strcpy(result->error_message, "Validation error");
        }

        return SILKWORM_OK;

    } catch (const std::exception& ex) {
        SILK_ERROR << "[Silkworm  ork Validator] Verify Chain failed: " << ex.what();

        return SILKWORM_INTERNAL_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_fork_validator_fork_choice_update(SilkwormHandle handle, bytes_32 head_hash_bytes, bytes_32 finalized_hash_bytes, bytes_32 safe_hash_bytes) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    if (!handle->execution_engine) {
        return SILKWORM_INTERNAL_ERROR;
    }

    silkworm::Hash head_hash{};
    memcpy(head_hash.bytes, head_hash_bytes.bytes, sizeof(head_hash.bytes));

    silkworm::Hash finalized_hash{};
    memcpy(finalized_hash.bytes, finalized_hash_bytes.bytes, sizeof(finalized_hash.bytes));
    std::optional<silkworm::Hash> finalized_hash_opt = finalized_hash ? std::optional<silkworm::Hash>(finalized_hash) : std::nullopt;

    silkworm::Hash safe_hash{};
    memcpy(safe_hash.bytes, safe_hash_bytes.bytes, sizeof(safe_hash.bytes));
    std::optional<silkworm::Hash> safe_hash_opt = safe_hash ? std::optional<silkworm::Hash>(safe_hash) : std::nullopt;

    try {
        auto result = handle->execution_engine->notify_fork_choice_update(head_hash, finalized_hash_opt, safe_hash_opt);

        if (result) {
            return SILKWORM_OK;
        } else {
            SILK_ERROR << "[Silkworm Fork Validator] Fork Choice Update failed with unknown error";
        }

    } catch (const std::exception& ex) {
        SILK_ERROR << "[Silkworm Fork Validator] Fork Choice Update failed: " << ex.what();
    }
    return SILKWORM_INTERNAL_ERROR;
}