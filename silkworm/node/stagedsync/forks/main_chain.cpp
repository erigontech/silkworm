// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "main_chain.hpp"

#include <set>

#include <gsl/util>
#include <magic_enum.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/stopwatch.hpp>

#include "extending_fork.hpp"

namespace {

//! @brief Handles the transaction lifecycle for long-standing and per-request transactions
class TransactionHandler {
  public:
    TransactionHandler(silkworm::datastore::kvdb::RWTxnManaged& txn, silkworm::datastore::kvdb::RWAccess& db_access, bool keep_db_txn_open = true)
        : txn_{txn}, db_access_{db_access}, keep_db_txn_open_{keep_db_txn_open} {
        if (!keep_db_txn_open_) {
            if (request_count_ == 0 && !txn_.is_open()) {
                txn_.reopen(*db_access_);
            }
            ++request_count_;
        } else {
            if (!txn_.is_open()) {
                txn_.reopen(*db_access_);
            }
        }
    }

    ~TransactionHandler() {
        if (!keep_db_txn_open_) {
            if (--request_count_ == 0) {
                txn_.commit_and_stop();
            }
        }
    }

  private:
    silkworm::datastore::kvdb::RWTxnManaged& txn_;
    silkworm::datastore::kvdb::RWAccess& db_access_;
    bool keep_db_txn_open_{true};
    static inline SILKWORM_THREAD_LOCAL int request_count_;
};
}  // namespace

namespace silkworm::stagedsync {

//! The number of inserted blocks between two successive commits on db
static constexpr uint64_t kInsertedBlockBatch{1'000};

using execution::api::InvalidChain;
using execution::api::ValidationError;
using execution::api::ValidChain;
using execution::api::VerificationResult;

MainChain::MainChain(
    boost::asio::any_io_executor executor,
    NodeSettings& ns,
    db::DataModelFactory data_model_factory,
    std::optional<TimerFactory> log_timer_factory,
    StageContainerFactory stages_factory,
    datastore::kvdb::RWAccess dba)
    : executor_{std::move(executor)},
      node_settings_{ns},
      data_model_factory_{std::move(data_model_factory)},
      log_timer_factory_{std::move(log_timer_factory)},
      stages_factory_{std::move(stages_factory)},
      db_access_{std::move(dba)},
      tx_{db_access_.start_rw_tx()},
      pipeline_{data_model_factory_, log_timer_factory_, stages_factory_},
      interim_canonical_chain_{tx_, data_model_factory_} {
    // We commit and close the one-and-only RW txn here because it must be reopened below in MainChain::open
    tx_.commit_and_stop();
}

void MainChain::open() {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};

    // Load last finalized and last chosen blocks from persistence
    auto last_finalized_hash = db::read_last_finalized_block(tx_);

    if (last_finalized_hash) {
        auto header = get_header(*last_finalized_hash);
        ensure_invariant(header.has_value(), "last finalized block not found in db");
        last_finalized_head_ = {header->number, *last_finalized_hash};
    } else {
        last_finalized_head_ = {0, node_settings_.chain_config.value().genesis_hash.value()};
    }

    auto last_head_hash = db::read_last_head_block(tx_);
    if (last_head_hash) {
        auto header = get_header(*last_head_hash);
        ensure_invariant(header.has_value(), "last head block not found in db");
        last_fork_choice_ = {header->number, *last_head_hash};
    } else
        last_fork_choice_ = last_finalized_head_;

    interim_canonical_chain_.open();

    // Revalidate chain by executing forward cycle up to the canonical current head at startup:
    // - if last cycle completed successfully, this will simply do nothing (no hurt)
    // - if last cycle was executed partially (i.e. not all stages are at the same block_num), this will do a cleanup cycle
    const auto& canonical_head{interim_canonical_chain_.current_head()};
    SILK_INFO << "Revalidate canonical chain up to number=" << canonical_head.block_num << " hash=" << to_hex(canonical_head.hash);

    forward(canonical_head.block_num, canonical_head.hash);

    // If forward cleanup cycle has not produced a valid chain, then we need to unwind
    if (!std::holds_alternative<ValidChain>(interim_head_status_)) {
        const auto unwind_point{pipeline_.unwind_point()};
        ensure_invariant(unwind_point.has_value(), "unwind point from pipeline requested when forward fails");
        unwind(*unwind_point);
    }
}

void MainChain::close() {
    if (node_settings_.keep_db_txn_open) {
        tx_.commit_and_stop();
    }
}

void MainChain::abort() {
    tx_.abort();
}

NodeSettings& MainChain::node_settings() {
    return node_settings_;
}

db::RWTxn& MainChain::tx() {
    return tx_;
}

const std::optional<TimerFactory>& MainChain::log_timer_factory() const {
    return log_timer_factory_;
}

datastore::StageScheduler& MainChain::stage_scheduler() const {
    return pipeline_.stage_scheduler();
}

BlockId MainChain::current_head() const {
    return interim_canonical_chain_.current_head();
}

BlockId MainChain::last_chosen_head() const {
    return last_fork_choice_;
}

BlockId MainChain::last_finalized_head() const {
    return last_finalized_head_;
}

std::optional<BlockId> MainChain::find_forking_point(const BlockHeader& header, const Hash& header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return interim_canonical_chain_.find_forking_point(header, header_hash);
}

std::optional<BlockId> MainChain::find_forking_point(const Hash& header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    auto header = get_header(header_hash);
    if (!header) return std::nullopt;
    return find_forking_point(*header, header_hash);
}

bool MainChain::is_finalized_canonical(BlockId block) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    if (block.block_num > last_fork_choice_.block_num) return false;
    return (interim_canonical_chain_.get_hash(block.block_num) == block.hash);
}

// protected, no txn handling required
Hash MainChain::insert_header(const BlockHeader& header) {
    return db::write_header_ex(tx_, header, /*with_header_numbers=*/true);
    // with_header_numbers=true is necessary at the moment because many getters here rely on kHeaderNumbers table;
    // that table is updated by stage block-hashes so only after a pipeline run
    // todo: remove getters that take only an hash as input and use with_header_numbers=false here
}

// protected, no txn handling required
void MainChain::insert_body(const Block& block, const Hash& block_hash) {
    // avoid calculation of block.header.hash() because is computationally expensive
    BlockNum block_num = block.header.number;

    if (data_model().has_body(block_num, block_hash)) return;

    db::write_body(tx_, block, block_hash, block_num);
}

void MainChain::insert_block(const Block& block) {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    Hash header_hash = insert_header(block.header);
    insert_body(block, header_hash);

    // Check chain integrity also on execution side (remove in production?)
    const auto parent = get_header(block.header.number - 1, block.header.parent_hash);
    ensure_invariant(parent.has_value(), "inserting block must have parent");

    // Commit inserted blocks once in a while not to lose downloading progress on restart
    static uint64_t block_count{0};
    if (++block_count == kInsertedBlockBatch) {
        block_count = 0;
        StopWatch timing{StopWatch::kStart};
        tx_.commit_and_renew();
        SILK_INFO << "MainChain::insert_block commit " << kInsertedBlockBatch << " blocks up to " << block.header.number
                  << " took " << StopWatch::format(timing.since_start());
    }
}

VerificationResult MainChain::verify_chain(Hash block_hash) {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    SILK_TRACE << "MainChain: verifying chain block=" << block_hash.to_hex();

    // Retrieve the block header to validate
    const auto block_header = get_header(block_hash);
    ensure_invariant(block_header.has_value(), "header to verify not found");

    // Check if incoming block already exists as canonical block
    if (is_canonical(block_header->number, block_hash)) {
        // The incoming block matches a block already on the canonical chain, verification is not always needed
        if (block_header->number <= last_fork_choice_.block_num) {
            // Last FCU block is greater than or equal to incoming canonical block, chain is valid up to last FCU block
            return ValidChain{last_fork_choice_.block_num, last_fork_choice_.hash};
        }
        if (std::holds_alternative<ValidChain>(interim_head_status_)) {
            // Chain is valid up to canonical head
            return ValidChain{interim_canonical_chain_.current_head().block_num, interim_canonical_chain_.current_head().hash};
        }
        if (std::holds_alternative<InvalidChain>(interim_head_status_)) {
            // Chain is valid up to unwind point
            const auto& invalid_chain{std::get<InvalidChain>(interim_head_status_)};
            if (block_header->number <= invalid_chain.unwind_point.block_num) {
                // Unwind point is greater than or equal incoming canonical block, chain is valid up to unwind point
                return ValidChain{invalid_chain.unwind_point.block_num, invalid_chain.unwind_point.hash};
            }
            // Incoming canonical block is greater than unwind point, so chain is invalid
            return invalid_chain;
        }
    }

    // db commit policy
    bool commit_at_each_stage = is_first_sync_;
    if (!commit_at_each_stage) tx_.disable_commit();
    auto _ = gsl::finally([&]() { tx_.enable_commit(); });

    // the new head is on a new fork?
    BlockId forking_point = interim_canonical_chain_.find_forking_point(*block_header, block_hash);  // the forking origin

    if (block_hash != interim_canonical_chain_.current_head().hash &&                   // if the new head is not the current head
        forking_point.block_num < interim_canonical_chain_.current_head().block_num) {  // and if the forking is behind the head
        // We need to do unwind to change canonical
        unwind(forking_point.block_num);
    }

    // update canonical up to header_hash
    interim_canonical_chain_.update_up_to(block_header->number, block_hash);

    // forward
    Stage::Result forward_result = pipeline_.forward(tx_, block_header->number);
    SILK_INFO << "MainChain::verify_chain forward_result=" << magic_enum::enum_name<>(forward_result);

    // evaluate result
    VerificationResult verify_result;
    switch (forward_result) {
        case Stage::Result::kSuccess: {
            ensure_invariant(pipeline_.head_header_number() == interim_canonical_chain_.current_head().block_num &&
                                 pipeline_.head_header_hash() == interim_canonical_chain_.current_head().hash,
                             "forward succeeded with pipeline head not aligned with canonical head");
            verify_result = ValidChain{pipeline_.head_header_number(), pipeline_.head_header_hash()};
            break;
        }
        case Stage::Result::kWrongFork:
        case Stage::Result::kInvalidBlock:
        case Stage::Result::kWrongStateRoot: {
            ensure_invariant(pipeline_.unwind_point().has_value(),
                             "unwind point from pipeline requested when forward fails");
            InvalidChain invalid_chain;
            invalid_chain.unwind_point.block_num = *pipeline_.unwind_point();
            invalid_chain.unwind_point.hash = *interim_canonical_chain_.get_hash(*pipeline_.unwind_point());
            if (pipeline_.bad_block()) {
                invalid_chain.bad_block = pipeline_.bad_block();
                invalid_chain.bad_headers = collect_bad_headers(tx_, invalid_chain);
            }
            verify_result = invalid_chain;
            break;
        }
        case Stage::Result::kStoppedByEnv:
            verify_result = ValidChain{pipeline_.head_header_number(), pipeline_.head_header_hash()};
            break;
        default:
            verify_result = ValidationError{
                .latest_valid_head = BlockId{pipeline_.head_header_number(), pipeline_.head_header_hash()},
            };
            break;
    }
    interim_head_status_ = verify_result;

    return verify_result;
}

bool MainChain::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    if (finalized_block_hash && !interim_canonical_chain_.has(*finalized_block_hash)) {
        return false;  // finalized block not found
    }

    const auto head_block_num{get_block_num(head_block_hash)};
    ensure_invariant(head_block_num.has_value(), "unknown block number for head block hash");
    if (is_canonical_head_ancestor(head_block_hash) && head_block_num <= last_fork_choice_.block_num) {
        // FCU selects an old canonical block already targeted by a previous FCU
        return true;
    }

    // Usually FCU must follow verify_chain with the same header except when:
    // 1) (PoS) CL is syncing so head_block_hash is referring to a previous valid head
    // 2) (PoW) previous verify_chain returned InvalidChain so CL is issuing a FCU with a previous valid head

    // When FCU selects a non-canonical block or our last validation result is not valid, we need to verify the resulting chain
    if (!interim_canonical_chain_.has(head_block_hash) || !std::holds_alternative<ValidChain>(interim_head_status_)) {
        verify_chain(head_block_hash);  // this will reset canonical chain to head_block_hash
        ensure_invariant(interim_canonical_chain_.current_head().hash == head_block_hash,
                         "canonical head not aligned with fork choice");
    }

    if (!std::holds_alternative<ValidChain>(interim_head_status_)) {
        return false;  // canonical head is not valid
    }

    const auto valid_chain = std::get<ValidChain>(interim_head_status_);
    ensure_invariant(interim_canonical_chain_.current_head() == valid_chain.current_head,
                     "canonical head not aligned with saved head status");

    last_fork_choice_.block_num = *head_block_num;
    last_fork_choice_.hash = head_block_hash;

    db::write_last_head_block(tx_, last_fork_choice_.hash);
    if (finalized_block_hash) {
        db::write_last_finalized_block(tx_, *finalized_block_hash);

        const auto finalized_block_num = get_block_num(*finalized_block_hash);
        last_finalized_head_.block_num = *finalized_block_num;
        last_finalized_head_.hash = *finalized_block_hash;
    }

    tx_.commit_and_renew();

    is_first_sync_ = false;

    return true;
}

// protected, no txn handling required
std::set<Hash> MainChain::collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain) {
    if (!invalid_chain.bad_block) return {};

    const auto bad_count{interim_canonical_chain_.current_head().block_num - invalid_chain.unwind_point.block_num};
    SILK_INFO << "MainChain::collect_bad_headers bad_count=" << bad_count << " skip=" << (bad_count > 10);

    // Do not collect too many headers, rather skip
    if (bad_count > 10) {
        return {};
    }

    std::set<Hash> bad_headers;
    for (BlockNum current_block_num = interim_canonical_chain_.current_head().block_num;
         current_block_num > invalid_chain.unwind_point.block_num; --current_block_num) {
        auto current_hash = db::read_canonical_header_hash(tx, current_block_num);
        bad_headers.insert(*current_hash);
    }

    /*  todo: check if we need also the following code (remember that this entire algo changed in Erigon)
    BlockNum new_block_num = unwind_point;
    if (is_bad_block) {
        bad_headers.insert(*bad_block);

        auto [max_block_num, max_hash] = header_with_biggest_td(tx, &bad_headers);

        if (max_block_num == 0) {
            max_block_num = unwind_point;
            max_hash = *db::read_canonical_header_hash(tx, max_block_num);
        }

        db::write_head_header_hash(tx, max_hash);
        new_block_num = max_block_num;
    }
    return {bad_headers, new_block_num};
    */
    return bad_headers;
}

std::unique_ptr<ExtendingFork> MainChain::fork(BlockId forking_point) {
    ensure(std::holds_alternative<ValidChain>(interim_head_status_), "forking is allowed from a valid state");
    return std::make_unique<ExtendingFork>(forking_point, *this, executor_);
}

void MainChain::reintegrate_fork(ExtendingFork& extending_fork) {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    Fork* fork = extending_fork.fork_.get();

    ensure(fork->head_status() && std::holds_alternative<ValidChain>(*fork->head_status()),
           "fork to be reintegrated must be valid");

    fork->flush(tx_);  // this must be done here, in the tx_ thread, due to MDBX limitations

    tx_.commit_and_renew();

    interim_canonical_chain_.set_current_head(fork->current_head());
    interim_head_status_ = *fork->head_status();
    last_fork_choice_ = fork->current_head();
    last_finalized_head_ = fork->finalized_head();
}

std::optional<BlockHeader> MainChain::get_header(Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    // const BlockHeader* cached = header_cache_.get(header_hash);
    // if (cached) {
    //     return *cached;
    // }
    return data_model().read_header(header_hash);
}

std::optional<BlockHeader> MainChain::get_header(BlockNum header_block_num, Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    // const BlockHeader* cached = header_cache_.get(header_hash);
    // if (cached) {
    //     return *cached;
    // }
    std::optional<BlockHeader> header = data_model().read_header(header_block_num, header_hash);
    return header;
}

std::optional<Hash> MainChain::get_finalized_canonical_hash(BlockNum block_num) const {
    if (block_num > last_fork_choice_.block_num) return {};
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return interim_canonical_chain_.get_hash(block_num);
}

std::optional<TotalDifficulty> MainChain::get_header_td(BlockNum header_block_num, Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return db::read_total_difficulty(tx_, header_block_num, header_hash);
}

std::optional<TotalDifficulty> MainChain::get_header_td(Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    auto header = get_header(header_hash);
    if (!header) return {};
    return db::read_total_difficulty(tx_, header->number, header_hash);
}

std::optional<BlockBody> MainChain::get_body(Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    BlockBody body;
    bool found = data_model().read_body(header_hash, body);
    if (!found) return {};
    return body;
}

BlockNum MainChain::get_block_progress() const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return data_model().max_block_num();
}

std::vector<BlockHeader> MainChain::get_last_headers(uint64_t limit) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    std::vector<BlockHeader> headers;

    data_model().for_last_n_headers(limit, [&headers](BlockHeader header) {
        headers.emplace_back(std::move(header));
    });

    return headers;
}

std::optional<BlockNum> MainChain::get_block_num(Hash header_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return data_model().read_block_num(header_hash);
}

BlockNum MainChain::max_frozen_block_num() const {
    return data_model().max_frozen_block_num();
}

bool MainChain::is_ancestor(BlockId supposed_parent, BlockId block) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return extends(block, supposed_parent);
}

bool MainChain::extends_last_fork_choice(BlockNum block_num, Hash hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    return extends({block_num, hash}, last_fork_choice_);
}

bool MainChain::extends(BlockId block, BlockId supposed_parent) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    while (block.block_num > supposed_parent.block_num) {
        auto header = get_header(block.block_num, block.hash);
        if (!header) return false;
        if (header->parent_hash == supposed_parent.hash) return true;
        --block.block_num;
        block.hash = header->parent_hash;
    }
    if (block.block_num == supposed_parent.block_num) return block.hash == supposed_parent.hash;

    return false;
}

bool MainChain::is_finalized_canonical(Hash block_hash) const {
    TransactionHandler tx_handler{tx_, db_access_, node_settings_.keep_db_txn_open};
    auto header = get_header(block_hash);
    if (!header) return false;
    if (header->number > last_fork_choice_.block_num) return false;
    auto canonical_hash_at_same_block_num = interim_canonical_chain_.get_hash(header->number);
    return canonical_hash_at_same_block_num == block_hash;
}

// protected, no txn handling required
bool MainChain::is_canonical(BlockNum block_num, const Hash& block_hash) const {
    // Check if specified block already exists as canonical block
    return interim_canonical_chain_.get_hash(block_num) == block_hash;
}

// protected, no txn handling required
bool MainChain::is_canonical_head_ancestor(const Hash& block_hash) const {
    return interim_canonical_chain_.has(block_hash) && interim_canonical_chain_.current_head().hash != block_hash;
}

// protected, no txn handling required
void MainChain::forward(BlockNum head_block_num, const Hash& head_hash) {
    // update canonical up to header_hash
    interim_canonical_chain_.update_up_to(head_block_num, head_hash);

    // forward
    Stage::Result forward_result = pipeline_.forward(tx_, head_block_num);

    // evaluate result
    VerificationResult verify_result;
    switch (forward_result) {
        case Stage::Result::kSuccess: {
            ensure_invariant(pipeline_.head_header_number() == interim_canonical_chain_.current_head().block_num &&
                                 pipeline_.head_header_hash() == interim_canonical_chain_.current_head().hash,
                             "forward succeeded with pipeline head not aligned with canonical head");
            verify_result = ValidChain{pipeline_.head_header_number(), pipeline_.head_header_hash()};
            break;
        }
        case Stage::Result::kWrongFork:
        case Stage::Result::kInvalidBlock:
        case Stage::Result::kWrongStateRoot: {
            ensure_invariant(pipeline_.unwind_point().has_value(),
                             "unwind point from pipeline requested when forward fails");
            InvalidChain invalid_chain;
            invalid_chain.unwind_point.block_num = *pipeline_.unwind_point();
            invalid_chain.unwind_point.hash = *interim_canonical_chain_.get_hash(*pipeline_.unwind_point());
            if (pipeline_.bad_block()) {
                invalid_chain.bad_block = pipeline_.bad_block();
                invalid_chain.bad_headers = collect_bad_headers(tx_, invalid_chain);
            }
            verify_result = invalid_chain;
            break;
        }
        case Stage::Result::kStoppedByEnv:
            verify_result = ValidChain{pipeline_.head_header_number(), pipeline_.head_header_hash()};
            break;
        default:
            verify_result = ValidationError{
                .latest_valid_head = BlockId{pipeline_.head_header_number(), pipeline_.head_header_hash()},
            };
            break;
    }
    interim_head_status_ = verify_result;
}

// protected, no txn handling required
void MainChain::unwind(BlockNum unwind_point) {
    const auto unwind_result = pipeline_.unwind(tx_, unwind_point);
    success_or_throw(unwind_result);  // unwind must complete with success

    // Remove last part of canonical chain
    interim_canonical_chain_.delete_down_to(unwind_point);
}

}  // namespace silkworm::stagedsync
