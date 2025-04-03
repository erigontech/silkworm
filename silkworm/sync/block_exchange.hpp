// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/infra/concurrency/containers.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/messages/inbound_message.hpp>

namespace silkworm {

class SentryClient;

// public interface for block downloading
struct IBlockExchange : public ActiveComponent {
    ~IBlockExchange() override = default;

    // set the initial state of the sync
    virtual void initial_state(std::vector<BlockHeader> last_headers) = 0;

    enum class TargetTracking : uint8_t {
        kByAnnouncements,
        kByNewPayloads
    };

    // start downloading blocks from current_block_num
    virtual void download_blocks(BlockNum current_block_num, TargetTracking) = 0;

    // set a new target block to download, to use with TargetTracking::kByNewPayloads
    virtual void new_target_block(std::shared_ptr<Block> block) = 0;

    virtual void stop_downloading() = 0;

    // the queue to receive downloaded blocks
    using ResultQueue = ConcurrentQueue<Blocks>;
    virtual ResultQueue& result_queue() = 0;

    // true if the sync is in sync with the network
    virtual bool in_sync() const = 0;

    // the current block_num of the sync
    virtual BlockNum current_block_num() const = 0;

    /*[[thread_safe]]*/
    virtual void accept(std::shared_ptr<Message>) = 0;

    virtual const ChainConfig& chain_config() const = 0;

    virtual SentryClient& sentry() const = 0;
};

//! \brief Implement the logic needed to download headers and bodies
class BlockExchange : public IBlockExchange {
  public:
    BlockExchange(
        db::DataStoreRef data_store,
        SentryClient& sentry,
        const ChainConfig& chain_config,
        bool use_preverified_hashes);
    ~BlockExchange() override;

    void initial_state(std::vector<BlockHeader> last_headers) override;
    void download_blocks(BlockNum current_block_num, TargetTracking) override;
    void new_target_block(std::shared_ptr<Block> block) override;
    void stop_downloading() override;

    ResultQueue& result_queue() override;
    bool in_sync() const override;
    BlockNum current_block_num() const override;

    void accept(std::shared_ptr<Message>) override;
    /*[[long_running]]*/
    void execution_loop() override;

    const ChainConfig& chain_config() const override;
    SentryClient& sentry() const override;
    BlockNum last_pre_validated_block() const;

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>;  // used internally to store new messages

    void receive_message(std::shared_ptr<InboundMessage> message);
    size_t request_headers(time_point_t tp, size_t max_requests);
    size_t request_bodies(time_point_t tp, size_t max_requests);
    void collect_headers();
    void collect_bodies();
    void log_status();

    // only to reply remote peer's requests
    db::DataStoreRef data_store_;
    SentryClient& sentry_;
    const ChainConfig& chain_config_;
    HeaderChain header_chain_;
    BodySequence body_sequence_;
    NetworkStatistics statistics_;

    ResultQueue results_{};
    MessageQueue messages_{};  // thread safe queue where to receive messages from sentry
    std::atomic_bool in_sync_{false};
    std::atomic_bool downloading_active_{false};
    std::atomic<BlockNum> current_block_num_{0};
};

}  // namespace silkworm
