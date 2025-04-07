// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rpc_api_table.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/json_rpc/methods.hpp>

namespace silkworm::rpc::commands {

TEST_CASE("RpcApiTable empty spec", "[rpc][api]") {
    CHECK_NOTHROW(RpcApiTable{""});
}

//! Check if API table contains specified method in any form
static bool has_method(const RpcApiTable& t, const std::string& m) {
    return t.find_json_handler(m) || t.find_json_glaze_handler(m) || t.find_stream_handler(m);
}

//! Check if specified method is present or not in API table
static bool check_method(const RpcApiTable& table, const std::string& method, const bool present) {
    return has_method(table, method) == present;
}

// These presence checks should always mirror the content of docs/JSON-RPC-API.md

//! Ensure *supported* admin namespace subset is present or not
static void check_admin_namespace(const RpcApiTable& table, bool present) {
    CHECK(check_method(table, json_rpc::method::k_admin_nodeInfo, present));
    CHECK(check_method(table, json_rpc::method::k_admin_peers, present));
}

//! Ensure *supported* net namespace subset is present or not
static void check_net_namespace(const RpcApiTable& table, bool present) {
    CHECK(check_method(table, json_rpc::method::k_net_listening, present));
    CHECK(check_method(table, json_rpc::method::k_net_peerCount, present));
    CHECK(check_method(table, json_rpc::method::k_net_version, present));
}

//! Ensure *supported* eth namespace subset is present or not
static void check_eth_namespace(const RpcApiTable& table, bool present) {
    CHECK(check_method(table, json_rpc::method::k_eth_blockNumber, present));
    CHECK(check_method(table, json_rpc::method::k_eth_chainId, present));
    CHECK(check_method(table, json_rpc::method::k_eth_protocolVersion, present));
    CHECK(check_method(table, json_rpc::method::k_eth_syncing, present));
    CHECK(check_method(table, json_rpc::method::k_eth_gasPrice, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getUncleByBlockHashAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getUncleByBlockNumberAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getUncleCountByBlockHash, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getUncleCountByBlockNumber, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionByHash, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionByBlockHashAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getRawTransactionByHash, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getRawTransactionByBlockHashAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getRawTransactionByBlockNumberAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionByBlockNumberAndIndex, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionReceipt, present));
    CHECK(check_method(table, json_rpc::method::k_eth_estimateGas, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBalance, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getCode, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionCount, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getStorageAt, present));
    CHECK(check_method(table, json_rpc::method::k_eth_call, present));
    CHECK(check_method(table, json_rpc::method::k_eth_callMany, present));
    CHECK(check_method(table, json_rpc::method::k_eth_callBundle, present));
    CHECK(check_method(table, json_rpc::method::k_eth_createAccessList, present));
    CHECK(check_method(table, json_rpc::method::k_eth_newFilter, present));
    CHECK(check_method(table, json_rpc::method::k_eth_newBlockFilter, present));
    CHECK(check_method(table, json_rpc::method::k_eth_newPendingTransactionFilter, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getFilterLogs, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getFilterChanges, present));
    CHECK(check_method(table, json_rpc::method::k_eth_uninstallFilter, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getLogs, present));
    CHECK(check_method(table, json_rpc::method::k_eth_sendRawTransaction, present));
    CHECK(check_method(table, json_rpc::method::k_eth_sendTransaction, present));
    CHECK(check_method(table, json_rpc::method::k_eth_signTransaction, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getProof, present));
    CHECK(check_method(table, json_rpc::method::k_eth_mining, present));
    CHECK(check_method(table, json_rpc::method::k_eth_coinbase, present));
    CHECK(check_method(table, json_rpc::method::k_eth_hashrate, present));
    CHECK(check_method(table, json_rpc::method::k_eth_submitHashrate, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getWork, present));
    CHECK(check_method(table, json_rpc::method::k_eth_submitWork, present));
    CHECK(check_method(table, json_rpc::method::k_eth_subscribe, present));
    CHECK(check_method(table, json_rpc::method::k_eth_unsubscribe, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBlockByHash, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBlockTransactionCountByHash, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBlockByNumber, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBlockTransactionCountByNumber, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getBlockReceipts, present));
    CHECK(check_method(table, json_rpc::method::k_eth_getTransactionReceiptsByBlock, present));
    CHECK(check_method(table, json_rpc::method::k_eth_maxPriorityFeePerGas, present));
    CHECK(check_method(table, json_rpc::method::k_eth_feeHistory, present));
}

//! Ensure *supported* web3 namespace subset is present or not
static void check_web3_namespace(const RpcApiTable& table, bool present) {
    CHECK(check_method(table, json_rpc::method::k_web3_clientVersion, present));
    CHECK(check_method(table, json_rpc::method::k_web3_sha3, present));
}

TEST_CASE("RpcApiTable admin spec", "[rpc][api]") {
    RpcApiTable table{kAdminApiNamespace};
    check_admin_namespace(table, true);
    check_eth_namespace(table, false);
    check_net_namespace(table, false);
    check_web3_namespace(table, false);
}

TEST_CASE("RpcApiTable eth spec", "[rpc][api]") {
    RpcApiTable table{kEthApiNamespace};
    check_admin_namespace(table, false);
    check_eth_namespace(table, true);
    check_net_namespace(table, false);
    check_web3_namespace(table, false);
}

TEST_CASE("RpcApiTable default spec", "[rpc][api]") {
    RpcApiTable table{kDefaultEth1ApiSpec};
    check_admin_namespace(table, true);
    check_eth_namespace(table, true);
    check_net_namespace(table, true);
    check_web3_namespace(table, true);
}

}  // namespace silkworm::rpc::commands
