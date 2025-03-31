// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

namespace silkworm::rpc::json_rpc::method {

// Constants defined here have a different naming from our standard: k_<JSON_RPC_API>
// where <JSON_RPC_API> is *exactly* the JSON RPC API method

// NOLINTBEGIN(readability-identifier-naming)

inline constexpr const char* k_web3_clientVersion{"web3_clientVersion"};
inline constexpr const char* k_web3_sha3{"web3_sha3"};

inline constexpr const char* k_admin_nodeInfo{"admin_nodeInfo"};
inline constexpr const char* k_admin_peers{"admin_peers"};

inline constexpr const char* k_net_listening{"net_listening"};
inline constexpr const char* k_net_peerCount{"net_peerCount"};
inline constexpr const char* k_net_version{"net_version"};

inline constexpr const char* k_eth_blockNumber{"eth_blockNumber"};
inline constexpr const char* k_eth_chainId{"eth_chainId"};
inline constexpr const char* k_eth_protocolVersion{"eth_protocolVersion"};
inline constexpr const char* k_eth_syncing{"eth_syncing"};
inline constexpr const char* k_eth_gasPrice{"eth_gasPrice"};
inline constexpr const char* k_eth_getUncleByBlockHashAndIndex{"eth_getUncleByBlockHashAndIndex"};
inline constexpr const char* k_eth_getUncleByBlockNumberAndIndex{"eth_getUncleByBlockNumberAndIndex"};
inline constexpr const char* k_eth_getUncleCountByBlockHash{"eth_getUncleCountByBlockHash"};
inline constexpr const char* k_eth_getUncleCountByBlockNumber{"eth_getUncleCountByBlockNumber"};
inline constexpr const char* k_eth_getTransactionByHash{"eth_getTransactionByHash"};
inline constexpr const char* k_eth_getTransactionByBlockHashAndIndex{"eth_getTransactionByBlockHashAndIndex"};
inline constexpr const char* k_eth_getRawTransactionByHash{"eth_getRawTransactionByHash"};
inline constexpr const char* k_eth_getRawTransactionByBlockHashAndIndex{"eth_getRawTransactionByBlockHashAndIndex"};
inline constexpr const char* k_eth_getRawTransactionByBlockNumberAndIndex{"eth_getRawTransactionByBlockNumberAndIndex"};
inline constexpr const char* k_eth_getTransactionByBlockNumberAndIndex{"eth_getTransactionByBlockNumberAndIndex"};
inline constexpr const char* k_eth_getTransactionReceipt{"eth_getTransactionReceipt"};
inline constexpr const char* k_eth_estimateGas{"eth_estimateGas"};
inline constexpr const char* k_eth_getBalance{"eth_getBalance"};
inline constexpr const char* k_eth_getCode{"eth_getCode"};
inline constexpr const char* k_eth_getTransactionCount{"eth_getTransactionCount"};
inline constexpr const char* k_eth_getStorageAt{"eth_getStorageAt"};
inline constexpr const char* k_eth_call{"eth_call"};
inline constexpr const char* k_eth_callMany{"eth_callMany"};
inline constexpr const char* k_eth_callBundle{"eth_callBundle"};
inline constexpr const char* k_eth_createAccessList{"eth_createAccessList"};
inline constexpr const char* k_eth_newFilter{"eth_newFilter"};
inline constexpr const char* k_eth_newBlockFilter{"eth_newBlockFilter"};
inline constexpr const char* k_eth_newPendingTransactionFilter{"eth_newPendingTransactionFilter"};
inline constexpr const char* k_eth_getFilterLogs{"eth_getFilterLogs"};
inline constexpr const char* k_eth_getFilterChanges{"eth_getFilterChanges"};
inline constexpr const char* k_eth_uninstallFilter{"eth_uninstallFilter"};
inline constexpr const char* k_eth_getLogs{"eth_getLogs"};
inline constexpr const char* k_eth_sendRawTransaction{"eth_sendRawTransaction"};
inline constexpr const char* k_eth_sendTransaction{"eth_sendTransaction"};
inline constexpr const char* k_eth_signTransaction{"eth_signTransaction"};
inline constexpr const char* k_eth_getProof{"eth_getProof"};
inline constexpr const char* k_eth_mining{"eth_mining"};
inline constexpr const char* k_eth_coinbase{"eth_coinbase"};
inline constexpr const char* k_eth_hashrate{"eth_hashrate"};
inline constexpr const char* k_eth_submitHashrate{"eth_submitHashrate"};
inline constexpr const char* k_eth_getWork{"eth_getWork"};
inline constexpr const char* k_eth_submitWork{"eth_submitWork"};
inline constexpr const char* k_eth_subscribe{"eth_subscribe"};
inline constexpr const char* k_eth_unsubscribe{"eth_unsubscribe"};
inline constexpr const char* k_eth_getBlockByHash{"eth_getBlockByHash"};
inline constexpr const char* k_eth_getBlockTransactionCountByHash{"eth_getBlockTransactionCountByHash"};
inline constexpr const char* k_eth_getBlockByNumber{"eth_getBlockByNumber"};
inline constexpr const char* k_eth_getBlockTransactionCountByNumber{"eth_getBlockTransactionCountByNumber"};
inline constexpr const char* k_eth_getBlockReceipts{"eth_getBlockReceipts"};
inline constexpr const char* k_eth_getTransactionReceiptsByBlock{"eth_getTransactionReceiptsByBlock"};
inline constexpr const char* k_eth_maxPriorityFeePerGas{"eth_maxPriorityFeePerGas"};
inline constexpr const char* k_eth_feeHistory{"eth_feeHistory"};
inline constexpr const char* k_eth_blobBaseFee{"eth_blobBaseFee"};
inline constexpr const char* k_eth_baseFee{"eth_baseFee"};

inline constexpr const char* k_debug_accountRange{"debug_accountRange"};
inline constexpr const char* k_debug_getModifiedAccountsByNumber{"debug_getModifiedAccountsByNumber"};
inline constexpr const char* k_debug_getModifiedAccountsByHash{"debug_getModifiedAccountsByHash"};
inline constexpr const char* k_debug_storageRangeAt{"debug_storageRangeAt"};
inline constexpr const char* k_debug_accountAt{"debug_accountAt"};
inline constexpr const char* k_debug_traceTransaction{"debug_traceTransaction"};
inline constexpr const char* k_debug_traceCall{"debug_traceCall"};
inline constexpr const char* k_debug_traceCallMany{"debug_traceCallMany"};
inline constexpr const char* k_debug_traceBlockByNumber{"debug_traceBlockByNumber"};
inline constexpr const char* k_debug_traceBlockByHash{"debug_traceBlockByHash"};
inline constexpr const char* k_debug_getRawBlock{"debug_getRawBlock"};
inline constexpr const char* k_debug_getRawHeader{"debug_getRawHeader"};
inline constexpr const char* k_debug_getRawTransaction{"debug_getRawTransaction"};
inline constexpr const char* k_debug_getRawReceipts{"debug_getRawReceipts"};

inline constexpr const char* k_trace_call{"trace_call"};
inline constexpr const char* k_trace_callMany{"trace_callMany"};
inline constexpr const char* k_trace_rawTransaction{"trace_rawTransaction"};
inline constexpr const char* k_trace_replayBlockTransactions{"trace_replayBlockTransactions"};
inline constexpr const char* k_trace_replayTransaction{"trace_replayTransaction"};
inline constexpr const char* k_trace_block{"trace_block"};
inline constexpr const char* k_trace_filter{"trace_filter"};
inline constexpr const char* k_trace_get{"trace_get"};
inline constexpr const char* k_trace_transaction{"trace_transaction"};

inline constexpr const char* k_erigon_blockNumber{"erigon_blockNumber"};
inline constexpr const char* k_erigon_cacheCheck{"erigon_cacheCheck"};
inline constexpr const char* k_erigon_getBalanceChangesInBlock{"erigon_getBalanceChangesInBlock"};
inline constexpr const char* k_erigon_getBlockByTimestamp{"erigon_getBlockByTimestamp"};
inline constexpr const char* k_erigon_getBlockReceiptsByBlockHash{"erigon_getBlockReceiptsByBlockHash"};
inline constexpr const char* k_erigon_getHeaderByHash{"erigon_getHeaderByHash"};
inline constexpr const char* k_erigon_getHeaderByNumber{"erigon_getHeaderByNumber"};
inline constexpr const char* k_erigon_getLatestLogs{"erigon_getLatestLogs"};
inline constexpr const char* k_erigon_getLogsByHash{"erigon_getLogsByHash"};
inline constexpr const char* k_erigon_forks{"erigon_forks"};
inline constexpr const char* k_erigon_watchTheBurn{"erigon_watchTheBurn"};
inline constexpr const char* k_erigon_nodeInfo{"erigon_nodeInfo"};

inline constexpr const char* k_parity_listStorageKeys{"parity_listStorageKeys"};

inline constexpr const char* k_engine_exchangeCapabilities{"engine_exchangeCapabilities"};
inline constexpr const char* k_engine_getClientVersionV1{"engine_getClientVersionV1"};
inline constexpr const char* k_engine_getPayloadV1{"engine_getPayloadV1"};
inline constexpr const char* k_engine_getPayloadV2{"engine_getPayloadV2"};
inline constexpr const char* k_engine_getPayloadV3{"engine_getPayloadV3"};
inline constexpr const char* k_engine_getPayloadV4{"engine_getPayloadV4"};
inline constexpr const char* k_engine_getPayloadBodiesByHashV1{"engine_getPayloadBodiesByHashV1"};
inline constexpr const char* k_engine_getPayloadBodiesByRangeV1{"engine_getPayloadBodiesByRangeV1"};
inline constexpr const char* k_engine_newPayloadV1{"engine_newPayloadV1"};
inline constexpr const char* k_engine_newPayloadV2{"engine_newPayloadV2"};
inline constexpr const char* k_engine_newPayloadV3{"engine_newPayloadV3"};
inline constexpr const char* k_engine_newPayloadV4{"engine_newPayloadV4"};
inline constexpr const char* k_engine_forkchoiceUpdatedV1{"engine_forkchoiceUpdatedV1"};
inline constexpr const char* k_engine_forkchoiceUpdatedV2{"engine_forkchoiceUpdatedV2"};
inline constexpr const char* k_engine_forkchoiceUpdatedV3{"engine_forkchoiceUpdatedV3"};
inline constexpr const char* k_engine_exchangeTransitionConfiguration{"engine_exchangeTransitionConfigurationV1"};

inline constexpr const char* k_txpool_status{"txpool_status"};
inline constexpr const char* k_txpool_content{"txpool_content"};

inline constexpr const char* k_ots_getApiLevel{"ots_getApiLevel"};
inline constexpr const char* k_ots_hasCode{"ots_hasCode"};
inline constexpr const char* k_ots_getBlockDetails{"ots_getBlockDetails"};
inline constexpr const char* k_ots_getBlockDetailsByHash{"ots_getBlockDetailsByHash"};
inline constexpr const char* k_ots_getBlockTransactions{"ots_getBlockTransactions"};
inline constexpr const char* k_ots_getTransactionBySenderAndNonce{"ots_getTransactionBySenderAndNonce"};
inline constexpr const char* k_ots_getContractCreator{"ots_getContractCreator"};
inline constexpr const char* k_ots_traceTransaction{"ots_traceTransaction"};
inline constexpr const char* k_ots_getTransactionError{"ots_getTransactionError"};
inline constexpr const char* k_ots_getInternalOperations{"ots_getInternalOperations"};
inline constexpr const char* k_ots_search_transactions_after{"ots_searchTransactionsAfter"};
inline constexpr const char* k_ots_search_transactions_before{"ots_searchTransactionsBefore"};

// NOLINTEND(readability-identifier-naming)

}  // namespace silkworm::rpc::json_rpc::method
