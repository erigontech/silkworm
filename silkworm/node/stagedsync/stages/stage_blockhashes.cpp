// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_blockhashes.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/endian.hpp>

namespace silkworm::stagedsync {

using datastore::etl::Entry;
using datastore::kvdb::Collector;

namespace db {
    using namespace silkworm::db;
}

Stage::Result BlockHashes::forward(db::RWTxn& txn) {
    /*
     * Creates HeaderNumber index by transforming
     *      from CanonicalHashes bucket : BlockNum ->  HeaderHash
     *        to HeaderNumber bucket    : HeaderHash  ->  BlockNum
     */

    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kForward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto headers_stage_progress{db::stages::read_stage_progress(txn, db::stages::kHeadersKey)};

        if (previous_progress == headers_stage_progress) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }
        if (previous_progress > headers_stage_progress) {
            // Something bad had happened.
            // Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "BlockHashes progress " + std::to_string(previous_progress) +
                                 " greater than Headers progress " + std::to_string(headers_stage_progress));
        }
        const BlockNum segment_width{headers_stage_progress - previous_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(headers_stage_progress),
                       "span", std::to_string(segment_width)});
        }

        collector_ = std::make_unique<Collector>(etl_settings_);
        collect_and_load(txn, previous_progress, headers_stage_progress);
        update_progress(txn, reached_block_num_);
        txn.commit_and_renew();

    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    collector_.reset();
    return ret;
}

Stage::Result BlockHashes::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
    try {
        throw_if_stopping();

        const auto previous_progress{get_progress(txn)};
        if (previous_progress <= to) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        update_progress(txn, to);
        txn.commit_and_renew();

    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return ret;
}

Stage::Result BlockHashes::prune(db::RWTxn&) { return Stage::Result::kSuccess; }

std::vector<std::string> BlockHashes::get_log_progress() {
    if (!is_stopping()) {
        switch (current_phase_) {
            case 1:
                return {"from", db::table::kCanonicalHashes.name_str(), "to", "etl",
                        "block", std::to_string(reached_block_num_)};
            case 2:
                return {"from", "etl",
                        "to", db::table::kHeaderNumbers.name_str(),
                        "key", collector_ ? collector_->get_load_key() : ""};
            default:
                break;
        }
    }
    return {};
}

void BlockHashes::collect_and_load(db::RWTxn& txn, const BlockNum from, const BlockNum to) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    reached_block_num_ = 0;
    current_phase_ = 1;  // Collect
    auto expected_block_num{from + 1};
    auto header_key{db::block_key(expected_block_num)};
    auto canon_hashes_cursor = txn.rw_cursor(db::table::kCanonicalHashes);
    auto data = canon_hashes_cursor->find(datastore::kvdb::to_slice(header_key), /*throw_notfound=*/false);
    while (data.done) {
        reached_block_num_ = endian::load_big_u64(static_cast<uint8_t*>(data.key.data()));
        if (reached_block_num_ > to) {
            --reached_block_num_;
            break;
        }

        // Sanity
        check_block_sequence(reached_block_num_, expected_block_num);
        if (data.value.length() != kHashLength) {
            throw StageError(Stage::Result::kDbError, "Invalid value length " + std::to_string(data.value.length()) +
                                                          " expected " + std::to_string(kHashLength));
        }

        collector_->collect(Entry{Bytes{datastore::kvdb::from_slice(data.value)}, operation_ == OperationType::kForward
                                                                                      ? Bytes{datastore::kvdb::from_slice(data.key)}
                                                                                      : Bytes{}});

        // Do we need to abort ?
        if (auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            log_time = now + 5s;
        }

        ++expected_block_num;
        data = canon_hashes_cursor->to_next(/*throw_notfound=*/false);
    }

    current_phase_ = 2;  // Load
    auto header_numbers_cursor = txn.rw_cursor_dup_sort(db::table::kHeaderNumbers);
    const MDBX_put_flags_t db_flags{header_numbers_cursor->empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT};
    collector_->load(*header_numbers_cursor, nullptr, db_flags);
}

}  // namespace silkworm::stagedsync
