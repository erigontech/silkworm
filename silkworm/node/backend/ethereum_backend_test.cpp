// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ethereum_backend.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("EthereumBackEnd", "[silkworm][backend][ethereum_backend]") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());

    datastore::kvdb::EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = true;
    db_config.in_memory = true;
    auto chaindata_env = datastore::kvdb::open_env(db_config);
    datastore::kvdb::ROAccess chaindata{chaindata_env};

    NodeSettings node_settings;

    std::shared_ptr<sentry::api::SentryClient> null_sentry_client;

    SECTION("EthereumBackEnd::EthereumBackEnd", "[silkworm][backend][ethereum_backend]") {
        EthereumBackEnd backend{node_settings, chaindata, null_sentry_client};
        CHECK(backend.node_name() == std::string{kDefaultNodeName});
        CHECK(!backend.etherbase());
        CHECK(backend.state_change_source() != nullptr);
    }

    SECTION("EthereumBackEnd::set_node_name", "[silkworm][backend][ethereum_backend]") {
        const std::string node_name{"server_name"};
        EthereumBackEnd backend{node_settings, chaindata, null_sentry_client};
        backend.set_node_name(node_name);
        CHECK(backend.node_name() == node_name);
    }

    SECTION("EthereumBackEnd::etherbase", "[silkworm][backend][ethereum_backend]") {
        node_settings.etherbase = 0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address;
        EthereumBackEnd backend{node_settings, chaindata, null_sentry_client};
        CHECK(backend.etherbase() == 0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address);
    }

    SECTION("EthereumBackEnd::close", "[silkworm][backend][ethereum_backend]") {
        EthereumBackEnd backend{node_settings, chaindata, null_sentry_client};
        CHECK_NOTHROW(backend.close());
    }
}

}  // namespace silkworm
