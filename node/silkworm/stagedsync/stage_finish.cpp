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

namespace silkworm::stagedsync {

StageResult Finish::forward(db::RWTxn& txn) {
    StageResult ret{StageResult::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress == execution_stage_progress) {
            // Nothing to process
            return ret;
        } else if (previous_progress > execution_stage_progress) {
            // Something bad had happened.
            std::string what{std::string(stage_name_) + " progress " + std::to_string(previous_progress) +
                             " while " + std::string(db::stages::kExecutionKey) + " stage " +
                             std::to_string(execution_stage_progress)};
            throw StageError(StageResult::kInvalidProgress, what);
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
        ret = static_cast<StageResult>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}
StageResult Finish::unwind(db::RWTxn& txn) {
    StageResult ret{StageResult::kSuccess};
    if (!sync_context_->unwind_to.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_to.value()};
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
        ret = static_cast<StageResult>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}
}  // namespace silkworm::stagedsync
