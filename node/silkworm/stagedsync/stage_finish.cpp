/*
   Copyright 2022 The Silkworm Authors

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

#include "stage_finish.hpp"

#include <silkworm/common/cast.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/internals/header_chain.hpp>

namespace silkworm::stagedsync {

Stage::Result Finish::forward(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress >= execution_stage_progress) {
            // Nothing to process
            const auto stop_at_block = stop_at_block_from_env();  // User can specify to stop at some block
            if (stop_at_block && stop_at_block <= execution_stage_progress) return Stage::Result::kStoppedByEnv;
            return ret;
        } else if (previous_progress > execution_stage_progress) {
            // Something bad had happened.
            std::string what{std::string(stage_name_) + " progress " + std::to_string(previous_progress) +
                             " while " + std::string(db::stages::kExecutionKey) + " stage " +
                             std::to_string(execution_stage_progress)};
            throw StageError(Stage::Result::kInvalidProgress, what);
        }

        throw_if_stopping();
        update_progress(txn, execution_stage_progress);

        // Log the new version of app at this height
        if (sync_context_->is_first_cycle) {
            Bytes build_info{byte_ptr_cast(node_settings_->build_info.data())};
            db::write_build_info_height(*txn, build_info, execution_stage_progress);
        }
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}
Stage::Result Finish::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};
    operation_ = OperationType::Unwind;
    try {
        throw_if_stopping();
        auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
        if (to >= previous_progress) return ret;
        throw_if_stopping();
        update_progress(txn, to);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}
}  // namespace silkworm::stagedsync
