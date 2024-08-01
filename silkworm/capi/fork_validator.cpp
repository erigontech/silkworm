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

    // return SILKWORM_OK;
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

SILKWORM_EXPORT int silkworm_fork_validator_verify_chain(SilkwormHandle handle, bytes_32 head_hash_bytes) SILKWORM_NOEXCEPT {
    silkworm::log::Info("Verifying chain");
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    if (!handle->execution_engine) {
        return SILKWORM_INTERNAL_ERROR;
    }

    silkworm::log::Info("Head hash bytes: " + silkworm::to_hex(head_hash_bytes.bytes, sizeof(head_hash_bytes.bytes)));

    silkworm::Hash head_hash{};
    memcpy(head_hash.bytes, head_hash_bytes.bytes, sizeof(head_hash.bytes));

    silkworm::log::Info("Head hash: " + silkworm::to_hex(head_hash.bytes, sizeof(head_hash.bytes)));

    auto result = handle->execution_engine->verify_chain_no_fork_tracking(head_hash);

    if (std::holds_alternative<silkworm::stagedsync::ValidChain>(result)) {
        return SILKWORM_OK;
    }

    return SILKWORM_INTERNAL_ERROR;
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
    std::optional<silkworm::Hash> finalized_hash_opt{};
    if (finalized_hash) {
        finalized_hash_opt = finalized_hash;
    }

    silkworm::Hash safe_hash{};
    memcpy(safe_hash.bytes, safe_hash_bytes.bytes, sizeof(safe_hash.bytes));
    std::optional<silkworm::Hash> safe_hash_opt{};
    if (safe_hash) {
        safe_hash_opt = safe_hash;
    }

    auto result = handle->execution_engine->notify_fork_choice_update(head_hash, finalized_hash_opt, safe_hash_opt);

    if (result) {
        return SILKWORM_OK;
    }

    return SILKWORM_INTERNAL_ERROR;
}