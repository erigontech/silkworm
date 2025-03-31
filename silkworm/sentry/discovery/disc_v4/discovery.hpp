// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

class DiscoveryImpl;

class Discovery {
  public:
    Discovery(
        const boost::asio::any_io_executor& executor,
        uint16_t server_port,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        std::function<discovery::enr::EnrRecord()> node_record,
        node_db::NodeDb& node_db);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    Task<void> run();

    void discover_more_needed();

  private:
    std::unique_ptr<DiscoveryImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery::disc_v4
