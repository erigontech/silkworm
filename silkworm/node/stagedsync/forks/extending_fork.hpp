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

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>

#include <silkworm/db/mdbx/memory_mutation.hpp>
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
    explicit ExtendingFork(BlockId forking_point, MainChain&, boost::asio::io_context&);
    ExtendingFork(const ExtendingFork&) = delete;
    ExtendingFork(ExtendingFork&& orig) = delete;  // not movable, it schedules methods execution in another thread
    ~ExtendingFork();

    // opening & closing
    void start_with(BlockId new_head, std::list<std::shared_ptr<Block>>&&);
    void close();

    // extension
    void extend_with(Hash head_hash, const Block& head);

    // verification
    concurrency::AwaitableFuture<VerificationResult> verify_chain();
    concurrency::AwaitableFuture<bool> fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    BlockId current_head() const;

  protected:
    friend MainChain;

    void execution_loop();

    void save_exception(std::exception_ptr);
    void propagate_exception_if_any();

    BlockId forking_point_;                              // starting point
    MainChain& main_chain_;                              // main chain
    boost::asio::io_context& io_context_;                // for io
    std::unique_ptr<Fork> fork_;                         // for domain logic
    std::unique_ptr<boost::asio::io_context> executor_;  // for pipeline execution
    std::thread thread_;                                 // for executor
    std::exception_ptr exception_{};                     // last exception

    // cached values provided to avoid thread synchronization
    BlockId current_head_{};
};

using ForkContainer = std::vector<std::unique_ptr<ExtendingFork>>;

// find the fork with the specified head
ForkContainer::iterator find_fork_by_head(ForkContainer& forks, const Hash& requested_head_hash);

// find the fork with the head to extend
ForkContainer::iterator find_fork_to_extend(ForkContainer& forks, const BlockHeader& header);

}  // namespace silkworm::stagedsync
