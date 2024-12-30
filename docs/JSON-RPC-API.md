## RPC API Implementation Status

The following table shows the current [JSON RPC API](https://eth.wiki/json-rpc/API) implementation status in `Silkworm RPCDaemon`.

| Command                                    | Availability |                   Notes                   | Integration | Performance |
|:-------------------------------------------|:------------:|:-----------------------------------------:|:-----------:|------------:|
| admin_nodeInfo                             |     Yes      |                                           |     Yes     |             |
| admin_peers                                |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| web3_clientVersion                         |     Yes      |                                           |     Yes     |             |
| web3_sha3                                  |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| net_listening                              |     Yes      | hard-coded (needs ethbackend integration) |     Yes     |             |
| net_peerCount                              |     Yes      |                                           |     Yes     |             |
| net_version                                |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| eth_blockNumber                            |     Yes      |                                           |     Yes     |             |
| eth_chainId                                |     Yes      |                                           |     Yes     |             |
| eth_protocolVersion                        |     Yes      |                                           |     Yes     |             |
| eth_syncing                                |     Yes      |                                           |     Yes     |             |
| eth_gasPrice                               |     Yes      |                                           |     Yes     |             |
| eth_maxPriorityFeePerGas                   |     Yes      |                                           |     Yes     |             |
| eth_feeHistory                             |     Yes      |                                           |     Yes     |             |
| eth_baseFee                                |     Yes      |                                           |     Yes     |             |
| eth_blobBaseFee                            |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| eth_getBlockByHash                         |     Yes      |                                           |     Yes     |     Yes     |
| eth_getBlockByNumber                       |     Yes      |                                           |     Yes     |     Yes     |
| eth_getBlockTransactionCountByHash         |     Yes      |                                           |     Yes     |             |
| eth_getBlockTransactionCountByNumber       |     Yes      |                                           |     Yes     |             |
| eth_getUncleByBlockHashAndIndex            |     Yes      |                                           |     Yes     |             |
| eth_getUncleByBlockNumberAndIndex          |     Yes      |                                           |     Yes     |             |
| eth_getUncleCountByBlockHash               |     Yes      |                                           |     Yes     |             |
| eth_getUncleCountByBlockNumber             |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| eth_getTransactionByHash                   |     Yes      |                                           |     Yes     |     Yes     |
| eth_getRawTransactionByHash                |     Yes      |                                           |     Yes     |             |
| eth_getTransactionByBlockHashAndIndex      |     Yes      |                                           |     Yes     |             |
| eth_getRawTransactionByBlockHashAndIndex   |     Yes      |                                           |     Yes     |             |
| eth_getTransactionByBlockNumberAndIndex    |     Yes      |                                           |     Yes     |             |
| eth_getRawTransactionByBlockNumberAndIndex |     Yes      |                                           |     Yes     |             |
| eth_getTransactionReceipt                  |     Yes      |  partial: retrieve receipts by exec txn   |     Yes     |     Yes     |
| eth_getBlockReceipts                       |     Yes      |                                           |     Yes     |             |
| eth_getTransactionReceiptsByBlock          |     Yes      |      same as eth_getBlockReceipts         |             |             |
|                                            |              |                                           |             |             |
| eth_estimateGas                            |     Yes      |                                           |     Yes     |             |
| eth_getBalance                             |     Yes      |                                           |     Yes     |     Yes     |
| eth_getCode                                |     Yes      |                                           |     Yes     |             |
| eth_getTransactionCount                    |     Yes      |                                           |     Yes     |             |
| eth_getStorageAt                           |     Yes      |                                           |     Yes     |             |
| eth_call                                   |     Yes      |                                           |     Yes     |     Yes     |
| eth_callMany                               |     Yes      |  partial: timeout param handling missing  |     Yes     |             |
| eth_callBundle                             |     Yes      |                                           |     Yes     |             |
| eth_createAccessList                       |     Yes      |                                           |     Yes     |     Yes     |
|                                            |              |                                           |             |             |
| eth_newFilter                              |     Yes      |                                           |             |             |
| eth_newBlockFilter                         |      -       |            not yet implemented            |             |             |
| eth_newPendingTransactionFilter            |      -       |            not yet implemented            |             |             |
| eth_getFilterChanges                       |     Yes      |                                           |             |             |
| eth_getFilterLogs                          |     Yes      |                                           |             |             |
| eth_uninstallFilter                        |     Yes      |                                           |             |             |
| eth_getLogs                                |     Yes      |                                           |     Yes     |     Yes     |
|                                            |              |                                           |             |             |
| eth_accounts                               |      No      |                deprecated                 |             |             |
| eth_sendRawTransaction                     |     Yes      |                remote only                |     Yes     |             |
| eth_sendTransaction                        |      -       |            not yet implemented            |             |             |
| eth_sign                                   |      No      |                deprecated                 |             |             |
| eth_signTransaction                        |      -       |                deprecated                 |             |             |
| eth_signTypedData                          |      -       |                   ????                    |             |             |
|                                            |              |                                           |             |             |
| eth_getProof                               |      -       |            not yet implemented            |             |             |
|                                            |              |                                           |             |             |
| eth_mining                                 |     Yes      |                                           |     Yes     |             |
| eth_coinbase                               |     Yes      |                                           |     Yes     |             |
| eth_hashrate                               |     Yes      |                                           |             |             |
| eth_submitHashrate                         |     Yes      |                                           |     Yes     |             |
| eth_getWork                                |     Yes      |                                           |     Yes     |             |
| eth_submitWork                             |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| eth_subscribe                              |      -       |   not yet implemented (WebSockets only)   |             |             |
| eth_unsubscribe                            |      -       |   not yet implemented (WebSockets only)   |             |             |
|                                            |              |                                           |             |             |
| engine_newPayloadV1                        |     Yes      |                                           |     Yes     |             |
| engine_newPayloadV2                        |     Yes      |                                           |     Yes     |             |
| engine_forkchoiceUpdatedV1                 |     Yes      |                                           |     Yes     |             |
| engine_forkchoiceUpdatedV2                 |     Yes      |                                           |     Yes     |             |
| engine_getPayloadV1                        |     Yes      |                                           |     Yes     |             |
| engine_getPayloadV2                        |     Yes      |                                           |     Yes     |             |
| engine_exchangeCapabilities                |     Yes      |                                           |     Yes     |             |
| engine_exchangeTransitionConfigurationV1   |     Yes      |                                           |     Yes     |             |
| engine_getPayloadBodiesByHashV1            |     Yes      |                                           |     Yes     |             |
| engine_getPayloadBodiesByRangeV1           |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| debug_accountRange                         |     Yes      |                                           |     Yes     |             |
| debug_accountAt                            |     Yes      |                                           |     Yes     |             |
| debug_getModifiedAccountsByHash            |     Yes      |                                           |     Yes     |             |
| debug_getModifiedAccountsByNumber          |     Yes      |                                           |     Yes     |             |
| debug_getBadBlocks                         |      No      |            data not available             |             |             |
| debug_getRawBlock                          |     Yes      |   can be optimized to avoid re-encoding   |             |             |
| debug_getRawHeader                         |     Yes      |                                           |             |             |
| debug_getRawReceipts                       |     Yes      |                                           |             |             |
| debug_getRawTransaction                    |     Yes      |                                           |             |             |
| debug_storageRangeAt                       |     Yes      |                                           |     Yes     |             |
| debug_traceBlockByHash                     |     Yes      |            uses JSON streaming            |     Yes     |             |
| debug_traceBlockByNumber                   |     Yes      |            uses JSON streaming            |     Yes     |             |
| debug_traceTransaction                     |     Yes      |            uses JSON streaming            |     Yes     |             |
| debug_traceCall                            |     Yes      |            uses JSON streaming            |     Yes     |             |
| debug_traceCallMany                        |     Yes      |            uses JSON streaming            |     Yes     |             |
|                                            |              |                                           |             |             |
| trace_call                                 |     Yes      |                                           |     Yes     |             |
| trace_callMany                             |     Yes      |                                           |     Yes     |             |
| trace_rawTransaction                       |     Yes      |                                           |     Yes     |             |
| trace_replayBlockTransactions              |     Yes      |                                           |     Yes     |             |
| trace_replayTransaction                    |     Yes      |                                           |     Yes     |             |
| trace_block                                |     Yes      |                                           |     Yes     |             |
| trace_filter                               |     Yes      |            uses JSON streaming            |     Yes     |             |
| trace_get                                  |     Yes      |                                           |     Yes     |             |
| trace_transaction                          |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| txpool_content                             |     Yes      |                                           |     Yes     |             |
| txpool_status                              |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| eth_getCompilers                           |      No      |                deprecated                 |             |             |
| eth_compileLLL                             |      No      |                deprecated                 |             |             |
| eth_compileSolidity                        |      No      |                deprecated                 |             |             |
| eth_compileSerpent                         |      No      |                deprecated                 |             |             |
|                                            |              |                                           |             |             |
| db_putString                               |      No      |                deprecated                 |             |             |
| db_getString                               |      No      |                deprecated                 |             |             |
| db_putHex                                  |      No      |                deprecated                 |             |             |
| db_getHex                                  |      No      |                deprecated                 |             |             |
|                                            |              |                                           |             |             |
| shh_post                                   |      No      |                deprecated                 |             |             |
| shh_version                                |      No      |                deprecated                 |             |             |
| shh_newIdentity                            |      No      |                deprecated                 |             |             |
| shh_hasIdentity                            |      No      |                deprecated                 |             |             |
| shh_newGroup                               |      No      |                deprecated                 |             |             |
| shh_addToGroup                             |      No      |                deprecated                 |             |             |
| shh_newFilter                              |      No      |                deprecated                 |             |             |
| shh_uninstallFilter                        |      No      |                deprecated                 |             |             |
| shh_getFilterChanges                       |      No      |                deprecated                 |             |             |
| shh_getMessages                            |      No      |                deprecated                 |             |             |
|                                            |              |                                           |             |             |
| erigon_cumulativeChainTraffic              |     Yes      |                                           |     Yes     |             |
| erigon_getHeaderByHash                     |     Yes      |                                           |     Yes     |             |
| erigon_getHeaderByNumber                   |     Yes      |                                           |     Yes     |             |
| erigon_getBalanceChangesInBlock            |     Yes      |                                           |     Yes     |             |
| erigon_getBlockByTimestamp                 |     Yes      |                                           |     Yes     |             |
| erigon_getBlockReceiptsByBlockHash         |     Yes      |                                           |     Yes     |             |
| erigon_getLogsByHash                       |     Yes      |                                           |     Yes     |             |
| erigon_forks                               |     Yes      |                                           |     Yes     |             |
| erigon_watchTheBurn                        |     Yes      |                                           |     Yes     |             |
| erigon_nodeInfo                            |     Yes      |                                           |     Yes     |             |
| erigon_blockNumber                         |     Yes      |                                           |     Yes     |             |
| erigon_cacheCheck                          |      -       |            not yet implemented            |             |             |
| erigon_getLatestLogs                       |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| bor_getSnapshot                            |      -       |            not yet implemented            |             |             |
| bor_getAuthor                              |      -       |            not yet implemented            |             |             |
| bor_getSnapshotAtHash                      |      -       |            not yet implemented            |             |             |
| bor_getSigners                             |      -       |            not yet implemented            |             |             |
| bor_getSignersAtHash                       |      -       |            not yet implemented            |             |             |
| bor_getCurrentProposer                     |      -       |            not yet implemented            |             |             |
| bor_getCurrentValidators                   |      -       |            not yet implemented            |             |             |
| bor_getRootHash                            |      -       |            not yet implemented            |             |             |
|                                            |              |                                           |             |             |
| parity_listStorageKeys                     |     Yes      |                                           |     Yes     |             |
|                                            |              |                                           |             |             |
| ots_getApiLevel                            |     Yes      |                                           |     Yes     |             |
| ots_getInternalOperations                  |     Yes      |                                           |     Yes     |             |
| ots_searchTransactionsBefore               |     Yes      |                                           |     Yes     |             |
| ots_searchTransactionsAfter                |     Yes      |                                           |     Yes     |             |
| ots_getBlockDetails                        |     Yes      |                                           |     Yes     |             |
| ots_getBlockDetailsByHash                  |     Yes      |                                           |     Yes     |             |
| ots_getBlockTransactions                   |     Yes      |                                           |     Yes     |             |
| ots_hasCode                                |     Yes      |                                           |     Yes     |             |
| ots_traceTransaction                       |     Yes      |                                           |     Yes     |             |
| ots_getTransactionError                    |     Yes      |                                           |     Yes     |             |
| ots_getTransactionBySenderAndNonce         |     Yes      |                                           |     Yes     |             |
| ots_getContractCreator                     |     Yes      |                                           |     Yes     |             |

This table is constantly updated. Please visit again.
