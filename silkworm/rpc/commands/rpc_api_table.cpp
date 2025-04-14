// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rpc_api_table.hpp"

#include <cstring>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/json_rpc/methods.hpp>

namespace silkworm::rpc::commands {

RpcApiTable::RpcApiTable(std::string_view api_spec) {
    build_handlers(api_spec);
}

std::optional<RpcApiTable::HandleMethod> RpcApiTable::find_json_handler(const std::string& method) const {
    const auto handle_method_pair = method_handlers_.find(method);
    if (handle_method_pair == method_handlers_.end()) {
        return std::nullopt;
    }
    return handle_method_pair->second;
}

std::optional<RpcApiTable::HandleMethodGlaze> RpcApiTable::find_json_glaze_handler(const std::string& method) const {
    const auto handle_method_pair = method_handlers_glaze_.find(method);
    if (handle_method_pair == method_handlers_glaze_.end()) {
        return std::nullopt;
    }
    return handle_method_pair->second;
}

std::optional<RpcApiTable::HandleStream> RpcApiTable::find_stream_handler(const std::string& method) const {
    const auto handle_method_pair = stream_handlers_.find(method);
    if (handle_method_pair == stream_handlers_.end()) {
        return std::nullopt;
    }
    return handle_method_pair->second;
}

void RpcApiTable::build_handlers(std::string_view api_spec) {
    size_t start = 0;
    size_t end = api_spec.find(kApiSpecSeparator);
    while (end != std::string::npos) {
        add_handlers(api_spec.substr(start, end - start));
        start = end + kApiSpecSeparator.length();
        end = api_spec.find(kApiSpecSeparator, start);
    }
    add_handlers(api_spec.substr(start, end));
}

void RpcApiTable::add_handlers(std::string_view api_namespace) {
    if (api_namespace == kAdminApiNamespace) {
        add_admin_handlers();
    } else if (api_namespace == kDebugApiNamespace) {
        add_debug_handlers();
    } else if (api_namespace == kEthApiNamespace) {
        add_eth_handlers();
    } else if (api_namespace == kNetApiNamespace) {
        add_net_handlers();
    } else if (api_namespace == kParityApiNamespace) {
        add_parity_handlers();
    } else if (api_namespace == kErigonApiNamespace) {
        add_erigon_handlers();
    } else if (api_namespace == kTraceApiNamespace) {
        add_trace_handlers();
    } else if (api_namespace == kWeb3ApiNamespace) {
        add_web3_handlers();
    } else if (api_namespace == kEngineApiNamespace) {
        add_engine_handlers();
    } else if (api_namespace == kTxPoolApiNamespace) {
        add_txpool_handlers();
    } else if (api_namespace == kOtterscanApiNamespace) {
        add_ots_handlers();
    } else {
        SILK_WARN << "Server::add_handlers invalid namespace [" << api_namespace << "] ignored";
    }
}

void RpcApiTable::add_admin_handlers() {
    method_handlers_[json_rpc::method::k_admin_nodeInfo] = &commands::RpcApi::handle_admin_node_info;
    method_handlers_[json_rpc::method::k_admin_peers] = &commands::RpcApi::handle_admin_peers;
}

void RpcApiTable::add_debug_handlers() {
    method_handlers_[json_rpc::method::k_debug_accountRange] = &commands::RpcApi::handle_debug_account_range;
    method_handlers_[json_rpc::method::k_debug_getModifiedAccountsByNumber] = &commands::RpcApi::handle_debug_get_modified_accounts_by_number;
    method_handlers_[json_rpc::method::k_debug_getModifiedAccountsByHash] = &commands::RpcApi::handle_debug_get_modified_accounts_by_hash;
    method_handlers_[json_rpc::method::k_debug_storageRangeAt] = &commands::RpcApi::handle_debug_storage_range_at;
    method_handlers_[json_rpc::method::k_debug_accountAt] = &commands::RpcApi::handle_debug_account_at;
    method_handlers_[json_rpc::method::k_debug_getRawBlock] = &commands::RpcApi::handle_debug_get_raw_block;
    method_handlers_[json_rpc::method::k_debug_getRawHeader] = &commands::RpcApi::handle_debug_get_raw_header;
    method_handlers_[json_rpc::method::k_debug_getRawTransaction] = &commands::RpcApi::handle_debug_get_raw_transaction;
    method_handlers_[json_rpc::method::k_debug_getRawReceipts] = &commands::RpcApi::handle_debug_get_raw_receipts;

    stream_handlers_[json_rpc::method::k_debug_traceCall] = &commands::RpcApi::handle_debug_trace_call;
    stream_handlers_[json_rpc::method::k_debug_traceCallMany] = &commands::RpcApi::handle_debug_trace_call_many;
    stream_handlers_[json_rpc::method::k_debug_traceTransaction] = &commands::RpcApi::handle_debug_trace_transaction;
    stream_handlers_[json_rpc::method::k_debug_traceBlockByNumber] = &commands::RpcApi::handle_debug_trace_block_by_number;
    stream_handlers_[json_rpc::method::k_debug_traceBlockByHash] = &commands::RpcApi::handle_debug_trace_block_by_hash;
}

void RpcApiTable::add_eth_handlers() {
    method_handlers_[json_rpc::method::k_eth_blockNumber] = &commands::RpcApi::handle_eth_block_num;
    method_handlers_[json_rpc::method::k_eth_chainId] = &commands::RpcApi::handle_eth_chain_id;
    method_handlers_[json_rpc::method::k_eth_protocolVersion] = &commands::RpcApi::handle_eth_protocol_version;
    method_handlers_[json_rpc::method::k_eth_syncing] = &commands::RpcApi::handle_eth_syncing;
    method_handlers_[json_rpc::method::k_eth_gasPrice] = &commands::RpcApi::handle_eth_gas_price;
    method_handlers_[json_rpc::method::k_eth_getBlockTransactionCountByHash] = &commands::RpcApi::handle_eth_get_block_transaction_count_by_hash;
    method_handlers_[json_rpc::method::k_eth_getBlockTransactionCountByNumber] = &commands::RpcApi::handle_eth_get_block_transaction_count_by_number;
    method_handlers_[json_rpc::method::k_eth_getUncleCountByBlockNumber] = &commands::RpcApi::handle_eth_get_uncle_count_by_block_num;
    method_handlers_[json_rpc::method::k_eth_getUncleCountByBlockHash] = &commands::RpcApi::handle_eth_get_uncle_count_by_block_hash;
    method_handlers_[json_rpc::method::k_eth_getTransactionByBlockHashAndIndex] = &commands::RpcApi::handle_eth_get_transaction_by_block_hash_and_index;
    method_handlers_[json_rpc::method::k_eth_getTransactionByBlockNumberAndIndex] = &commands::RpcApi::handle_eth_get_transaction_by_block_num_and_index;
    method_handlers_[json_rpc::method::k_eth_getRawTransactionByHash] = &commands::RpcApi::handle_eth_get_raw_transaction_by_hash;
    method_handlers_[json_rpc::method::k_eth_getRawTransactionByBlockHashAndIndex] = &commands::RpcApi::handle_eth_get_raw_transaction_by_block_hash_and_index;
    method_handlers_[json_rpc::method::k_eth_getRawTransactionByBlockNumberAndIndex] = &commands::RpcApi::handle_eth_get_raw_transaction_by_block_num_and_index;
    method_handlers_[json_rpc::method::k_eth_getTransactionReceipt] = &commands::RpcApi::handle_eth_get_transaction_receipt;
    method_handlers_[json_rpc::method::k_eth_estimateGas] = &commands::RpcApi::handle_eth_estimate_gas;
    method_handlers_[json_rpc::method::k_eth_getBalance] = &commands::RpcApi::handle_eth_get_balance;
    method_handlers_[json_rpc::method::k_eth_getCode] = &commands::RpcApi::handle_eth_get_code;
    method_handlers_[json_rpc::method::k_eth_getTransactionCount] = &commands::RpcApi::handle_eth_get_transaction_count;
    method_handlers_[json_rpc::method::k_eth_getStorageAt] = &commands::RpcApi::handle_eth_get_storage_at;
    method_handlers_[json_rpc::method::k_eth_callBundle] = &commands::RpcApi::handle_eth_call_bundle;
    method_handlers_[json_rpc::method::k_eth_createAccessList] = &commands::RpcApi::handle_eth_create_access_list;
    method_handlers_[json_rpc::method::k_eth_newFilter] = &commands::RpcApi::handle_eth_new_filter;
    method_handlers_[json_rpc::method::k_eth_newBlockFilter] = &commands::RpcApi::handle_eth_new_block_filter;
    method_handlers_[json_rpc::method::k_eth_newPendingTransactionFilter] = &commands::RpcApi::handle_eth_new_pending_transaction_filter;
    method_handlers_[json_rpc::method::k_eth_getFilterLogs] = &commands::RpcApi::handle_eth_get_filter_logs;
    method_handlers_[json_rpc::method::k_eth_getFilterChanges] = &commands::RpcApi::handle_eth_get_filter_changes;
    method_handlers_[json_rpc::method::k_eth_uninstallFilter] = &commands::RpcApi::handle_eth_uninstall_filter;
    method_handlers_[json_rpc::method::k_eth_sendRawTransaction] = &commands::RpcApi::handle_eth_send_raw_transaction;
    method_handlers_[json_rpc::method::k_eth_sendTransaction] = &commands::RpcApi::handle_eth_send_transaction;
    method_handlers_[json_rpc::method::k_eth_signTransaction] = &commands::RpcApi::handle_eth_sign_transaction;
    method_handlers_[json_rpc::method::k_eth_getProof] = &commands::RpcApi::handle_eth_get_proof;
    method_handlers_[json_rpc::method::k_eth_mining] = &commands::RpcApi::handle_eth_mining;
    method_handlers_[json_rpc::method::k_eth_coinbase] = &commands::RpcApi::handle_eth_coinbase;
    method_handlers_[json_rpc::method::k_eth_hashrate] = &commands::RpcApi::handle_eth_hashrate;
    method_handlers_[json_rpc::method::k_eth_submitHashrate] = &commands::RpcApi::handle_eth_submit_hashrate;
    method_handlers_[json_rpc::method::k_eth_getWork] = &commands::RpcApi::handle_eth_get_work;
    method_handlers_[json_rpc::method::k_eth_submitWork] = &commands::RpcApi::handle_eth_submit_work;
    method_handlers_[json_rpc::method::k_eth_subscribe] = &commands::RpcApi::handle_eth_subscribe;
    method_handlers_[json_rpc::method::k_eth_unsubscribe] = &commands::RpcApi::handle_eth_unsubscribe;
    method_handlers_[json_rpc::method::k_eth_getBlockReceipts] = &commands::RpcApi::handle_eth_get_block_receipts;
    method_handlers_[json_rpc::method::k_eth_getTransactionReceiptsByBlock] = &commands::RpcApi::handle_eth_get_block_receipts;
    method_handlers_[json_rpc::method::k_eth_maxPriorityFeePerGas] = &commands::RpcApi::handle_eth_max_priority_fee_per_gas;
    method_handlers_[json_rpc::method::k_eth_feeHistory] = &commands::RpcApi::handle_eth_fee_history;
    method_handlers_[json_rpc::method::k_eth_callMany] = &commands::RpcApi::handle_eth_call_many;
    method_handlers_[json_rpc::method::k_eth_baseFee] = &commands::RpcApi::handle_eth_base_fee;
    method_handlers_[json_rpc::method::k_eth_blobBaseFee] = &commands::RpcApi::handle_eth_blob_base_fee;

    // GLAZE methods
    method_handlers_glaze_[json_rpc::method::k_eth_getLogs] = &commands::RpcApi::handle_eth_get_logs;
    method_handlers_glaze_[json_rpc::method::k_eth_call] = &commands::RpcApi::handle_eth_call;
    method_handlers_glaze_[json_rpc::method::k_eth_getBlockByNumber] = &commands::RpcApi::handle_eth_get_block_by_number;
    method_handlers_glaze_[json_rpc::method::k_eth_getBlockByHash] = &commands::RpcApi::handle_eth_get_block_by_hash;
    method_handlers_glaze_[json_rpc::method::k_eth_getUncleByBlockHashAndIndex] = &commands::RpcApi::handle_eth_get_uncle_by_block_hash_and_index;
    method_handlers_glaze_[json_rpc::method::k_eth_getUncleByBlockNumberAndIndex] = &commands::RpcApi::handle_eth_get_uncle_by_block_num_and_index;
    method_handlers_glaze_[json_rpc::method::k_eth_getTransactionByHash] = &commands::RpcApi::handle_eth_get_transaction_by_hash;
}

void RpcApiTable::add_net_handlers() {
    method_handlers_[json_rpc::method::k_net_listening] = &commands::RpcApi::handle_net_listening;
    method_handlers_[json_rpc::method::k_net_peerCount] = &commands::RpcApi::handle_net_peer_count;
    method_handlers_[json_rpc::method::k_net_version] = &commands::RpcApi::handle_net_version;
}

void RpcApiTable::add_parity_handlers() {
    method_handlers_[json_rpc::method::k_parity_listStorageKeys] = &commands::RpcApi::handle_parity_list_storage_keys;
}

void RpcApiTable::add_erigon_handlers() {
    method_handlers_[json_rpc::method::k_erigon_blockNumber] = &commands::RpcApi::handle_erigon_block_num;
    method_handlers_[json_rpc::method::k_erigon_cacheCheck] = &commands::RpcApi::handle_erigon_cache_check;
    method_handlers_[json_rpc::method::k_erigon_getBalanceChangesInBlock] = &commands::RpcApi::handle_erigon_get_balance_changes_in_block;
    method_handlers_[json_rpc::method::k_erigon_getBlockReceiptsByBlockHash] = &commands::RpcApi::handle_erigon_get_block_receipts_by_block_hash;
    method_handlers_[json_rpc::method::k_erigon_getHeaderByHash] = &commands::RpcApi::handle_erigon_get_header_by_hash;
    method_handlers_[json_rpc::method::k_erigon_getHeaderByNumber] = &commands::RpcApi::handle_erigon_get_header_by_number;
    method_handlers_[json_rpc::method::k_erigon_getLatestLogs] = &commands::RpcApi::handle_erigon_get_latest_logs;
    method_handlers_[json_rpc::method::k_erigon_getLogsByHash] = &commands::RpcApi::handle_erigon_get_logs_by_hash;
    method_handlers_[json_rpc::method::k_erigon_forks] = &commands::RpcApi::handle_erigon_forks;
    method_handlers_[json_rpc::method::k_erigon_nodeInfo] = &commands::RpcApi::handle_erigon_node_info;

    // GLAZE methods
    method_handlers_glaze_[json_rpc::method::k_erigon_getBlockByTimestamp] = &commands::RpcApi::handle_erigon_get_block_by_timestamp;
}

void RpcApiTable::add_trace_handlers() {
    method_handlers_[json_rpc::method::k_trace_call] = &commands::RpcApi::handle_trace_call;
    method_handlers_[json_rpc::method::k_trace_callMany] = &commands::RpcApi::handle_trace_call_many;
    method_handlers_[json_rpc::method::k_trace_rawTransaction] = &commands::RpcApi::handle_trace_raw_transaction;
    method_handlers_[json_rpc::method::k_trace_replayBlockTransactions] = &commands::RpcApi::handle_trace_replay_block_transactions;
    method_handlers_[json_rpc::method::k_trace_replayTransaction] = &commands::RpcApi::handle_trace_replay_transaction;
    method_handlers_[json_rpc::method::k_trace_block] = &commands::RpcApi::handle_trace_block;
    method_handlers_[json_rpc::method::k_trace_get] = &commands::RpcApi::handle_trace_get;
    method_handlers_[json_rpc::method::k_trace_transaction] = &commands::RpcApi::handle_trace_transaction;

    stream_handlers_[json_rpc::method::k_trace_filter] = &commands::RpcApi::handle_trace_filter;
}

void RpcApiTable::add_web3_handlers() {
    method_handlers_[json_rpc::method::k_web3_clientVersion] = &commands::RpcApi::handle_web3_client_version;
    method_handlers_[json_rpc::method::k_web3_sha3] = &commands::RpcApi::handle_web3_sha3;
}

void RpcApiTable::add_engine_handlers() {
    method_handlers_[json_rpc::method::k_engine_exchangeCapabilities] = &commands::RpcApi::handle_engine_exchange_capabilities;
    method_handlers_[json_rpc::method::k_engine_getPayloadV1] = &commands::RpcApi::handle_engine_get_payload_v1;
    method_handlers_[json_rpc::method::k_engine_getPayloadV2] = &commands::RpcApi::handle_engine_get_payload_v2;
    method_handlers_[json_rpc::method::k_engine_getPayloadV3] = &commands::RpcApi::handle_engine_get_payload_v3;
    method_handlers_[json_rpc::method::k_engine_getPayloadV4] = &commands::RpcApi::handle_engine_get_payload_v4;
    method_handlers_[json_rpc::method::k_engine_getPayloadBodiesByHashV1] = &commands::RpcApi::handle_engine_get_payload_bodies_by_hash_v1;
    method_handlers_[json_rpc::method::k_engine_getPayloadBodiesByRangeV1] = &commands::RpcApi::handle_engine_get_payload_bodies_by_range_v1;
    method_handlers_[json_rpc::method::k_engine_newPayloadV1] = &commands::RpcApi::handle_engine_new_payload_v1;
    method_handlers_[json_rpc::method::k_engine_newPayloadV2] = &commands::RpcApi::handle_engine_new_payload_v2;
    method_handlers_[json_rpc::method::k_engine_newPayloadV3] = &commands::RpcApi::handle_engine_new_payload_v3;
    method_handlers_[json_rpc::method::k_engine_newPayloadV4] = &commands::RpcApi::handle_engine_new_payload_v4;
    method_handlers_[json_rpc::method::k_engine_forkchoiceUpdatedV1] = &commands::RpcApi::handle_engine_forkchoice_updated_v1;
    method_handlers_[json_rpc::method::k_engine_forkchoiceUpdatedV2] = &commands::RpcApi::handle_engine_forkchoice_updated_v2;
    method_handlers_[json_rpc::method::k_engine_forkchoiceUpdatedV3] = &commands::RpcApi::handle_engine_forkchoice_updated_v3;
    method_handlers_[json_rpc::method::k_engine_exchangeTransitionConfiguration] = &commands::RpcApi::handle_engine_exchange_transition_configuration_v1;

    method_handlers_glaze_[json_rpc::method::k_engine_getClientVersionV1] = &commands::RpcApi::handle_engine_get_client_version_v1;
}

void RpcApiTable::add_txpool_handlers() {
    method_handlers_[json_rpc::method::k_txpool_status] = &commands::RpcApi::handle_txpool_status;
    method_handlers_[json_rpc::method::k_txpool_content] = &commands::RpcApi::handle_txpool_content;
}

void RpcApiTable::add_ots_handlers() {
    method_handlers_[json_rpc::method::k_ots_getApiLevel] = &commands::RpcApi::handle_ots_get_api_level;
    method_handlers_[json_rpc::method::k_ots_hasCode] = &commands::RpcApi::handle_ots_has_code;
    method_handlers_[json_rpc::method::k_ots_getBlockDetails] = &commands::RpcApi::handle_ots_get_block_details;
    method_handlers_[json_rpc::method::k_ots_getBlockDetailsByHash] = &commands::RpcApi::handle_ots_get_block_details_by_hash;
    method_handlers_[json_rpc::method::k_ots_getBlockTransactions] = &commands::RpcApi::handle_ots_get_block_transactions;
    method_handlers_[json_rpc::method::k_ots_getTransactionBySenderAndNonce] = &commands::RpcApi::handle_ots_get_transaction_by_sender_and_nonce;
    method_handlers_[json_rpc::method::k_ots_getContractCreator] = &commands::RpcApi::handle_ots_get_contract_creator;
    method_handlers_[json_rpc::method::k_ots_traceTransaction] = &commands::RpcApi::handle_ots_trace_transaction;
    method_handlers_[json_rpc::method::k_ots_getTransactionError] = &commands::RpcApi::handle_ots_get_transaction_error;
    method_handlers_[json_rpc::method::k_ots_getInternalOperations] = &commands::RpcApi::handle_ots_get_internal_operations;
    method_handlers_[json_rpc::method::k_ots_search_transactions_before] = &commands::RpcApi::handle_ots_search_transactions_before;
    method_handlers_[json_rpc::method::k_ots_search_transactions_after] = &commands::RpcApi::handle_ots_search_transactions_after;
}

}  // namespace silkworm::rpc::commands
