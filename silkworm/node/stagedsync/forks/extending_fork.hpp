// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/db/datastore/kvdb/memory_mutation.hpp>
#include <silkworm/infra/concurrency/awaitable_future.hpp>

#include "fork.hpp"

namespace silkworm::stagedsync {

// ExtendingFork is a composition of a Fork, an in-memory database and an io_context.
// It executes the fork operations on the private io_context, so we can:
// - parallelize operations on different forks to improve performances
// - put operations on the same fork in sequence to avoid races
// The in-memory database is used to store the forked blocks & states.

class ExtendingFork {
  public:
    explicit ExtendingFork(
        BlockId forking_point,
        MainChain& main_chain,
        boost::asio::any_io_executor external_executor);
    ExtendingFork(const ExtendingFork&) = delete;
    ExtendingFork(ExtendingFork&& orig) = delete;  // not movable, it schedules methods execution in another thread
    ~ExtendingFork();

    // opening & closing
    void start_with(BlockId new_head, std::list<std::shared_ptr<Block>> blocks);
    void close();

    // extension
    void extend_with(Hash head_hash, const Block& head);

    // verification
    using VerificationResultFuture = concurrency::AwaitableFuture<execution::api::VerificationResult>;
    VerificationResultFuture verify_chain();
    concurrency::AwaitableFuture<bool> fork_choice(Hash head_block_hash,
                                                   std::optional<Hash> finalized_block_hash = {},
                                                   std::optional<Hash> safe_block_hash = {});

    // state
    BlockId current_head() const;

  protected:
    friend MainChain;

    void execution_loop();

    void save_exception(std::exception_ptr);
    void propagate_exception_if_any();

    // starting point
    BlockId forking_point_;

    MainChain& main_chain_;

    // for promises
    boost::asio::any_io_executor external_executor_;

    // for domain logic
    std::unique_ptr<Fork> fork_;

    // for pipeline execution
    std::unique_ptr<boost::asio::io_context> ioc_;

    // for executor
    std::thread thread_;

    // last exception
    std::exception_ptr exception_{};

    // cached values provided to avoid thread synchronization
    BlockId current_head_{};
};

using ForkContainer = std::vector<std::unique_ptr<ExtendingFork>>;

// find the fork with the specified head
ForkContainer::iterator find_fork_by_head(ForkContainer& forks, const Hash& requested_head_hash);

// find the fork with the head to extend
ForkContainer::iterator find_fork_to_extend(ForkContainer& forks, const BlockHeader& header);

}  // namespace silkworm::stagedsync
