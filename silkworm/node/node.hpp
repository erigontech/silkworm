// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/node/settings.hpp>

namespace silkworm::node {

class NodeImpl;

class Node {
  public:
    Node(
        rpc::ClientContextPool& context_pool,
        Settings& settings);
    ~Node();

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    Task<void> run();
    Task<void> wait_for_setup();

  private:
    std::unique_ptr<NodeImpl> p_impl_;
};

}  // namespace silkworm::node
