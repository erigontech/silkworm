## RPC API Implementation Status

The following table shows the current [JSON RPC API](https://eth.wiki/json-rpc/API) implementation status in `Silkrpc`.

| Command                                    | Availability |                                     Notes |
|:-------------------------------------------|:------------:|------------------------------------------:|
| admin_nodeInfo                             |     Yes      |                                           |
| admin_peers                                |     Yes      |                                           |
|                                            |              |                                           |
| web3_clientVersion                         |     Yes      |                                           |
| web3_sha3                                  |     Yes      |                                           |
|                                            |              |                                           |
| net_listening                              |     Yes      | hard-coded (needs ethbackend integration) |
| net_peerCount                              |     Yes      |                                           |
| net_version                                |     Yes      |                                           |
|                                            |              |                                           |
| eth_blockNumber                            |     Yes      |                                           |
| eth_chainId                                |     Yes      |                                           |
| eth_protocolVersion                        |     Yes      |                                           |
| eth_syncing                                |     Yes      |                                           |
| eth_gasPrice                               |     Yes      |                                           |
| eth_maxPriorityFeePerGas                   |     Yes      |                                           |
| eth_feeHistory                             |     Yes      |                                           |
|                                            |              |                                           |
| eth_getBlockByHash                         |     Yes      |                                           |
| eth_getBlockByNumber                       |     Yes      |                                           |
| eth_getBlockTransactionCountByHash         |     Yes      |                                           |
| eth_getBlockTransactionCountByNumber       |     Yes      |                                           |
| eth_getUncleByBlockHashAndIndex            |     Yes      |                                           |
| eth_getUncleByBlockNumberAndIndex          |     Yes      |                                           |
| eth_getUncleCountByBlockHash               |     Yes      |                                           |
| eth_getUncleCountByBlockNumber             |     Yes      |                                           |
|                                            |              |                                           |
| eth_getTransactionByHash                   |     Yes      |                     partially implemented |
| eth_getRawTransactionByHash                |     Yes      |                     partially implemented |
| eth_getTransactionByBlockHashAndIndex      |     Yes      |                                           |
| eth_getRawTransactionByBlockHashAndIndex   |     Yes      |                     partially implemented |
| eth_getTransactionByBlockNumberAndIndex    |     Yes      |                                           |
| eth_getRawTransactionByBlockNumberAndIndex |     Yes      |                     partially implemented |
| eth_getTransactionReceipt                  |     Yes      |                     partially implemented |
| eth_getBlockReceipts                       |     Yes      |           same as parity_getBlockReceipts |
| eth_getTransactionReceiptsByBlock          |     Yes      |           same as parity_getBlockReceipts |
|                                            |              |                                           |
| eth_estimateGas                            |     Yes      |                                           |
| eth_getBalance                             |     Yes      |                                           |
| eth_getCode                                |     Yes      |                                           |
| eth_getTransactionCount                    |     Yes      |                                           |
| eth_getStorageAt                           |     Yes      |                                           |
| eth_call                                   |     Yes      |                                           |
| eth_callMany                               |     Yes      |                     partially implemented |
| eth_callBundle                             |     Yes      |                                           |
| eth_createAccessList                       |     Yes      |                                           |
|                                            |              |                                           |
| eth_newFilter                              |     Yes      |                                           |
| eth_newBlockFilter                         |      -       |                       not yet implemented |
| eth_newPendingTransactionFilter            |      -       |                       not yet implemented |
| eth_getFilterChanges                       |     Yes      |                                           |
| eth_getFilterLogs                          |     Yes      |                                           |
| eth_uninstallFilter                        |     Yes      |                                           |
| eth_getLogs                                |     Yes      |                                           |
|                                            |              |                                           |
| eth_accounts                               |      No      |                                deprecated |
| eth_sendRawTransaction                     |     Yes      |                               remote only |
| eth_sendTransaction                        |      -       |                       not yet implemented |
| eth_sign                                   |      No      |                                deprecated |
| eth_signTransaction                        |      -       |                                deprecated |
| eth_signTypedData                          |      -       |                                      ???? |
|                                            |              |                                           |
| eth_getProof                               |      -       |                       not yet implemented |
|                                            |              |                                           |
| eth_mining                                 |     Yes      |                                           |
| eth_coinbase                               |     Yes      |                                           |
| eth_hashrate                               |     Yes      |                                           |
| eth_submitHashrate                         |     Yes      |                                           |
| eth_getWork                                |     Yes      |                                           |
| eth_submitWork                             |     Yes      |                                           |
|                                            |              |                                           |
| eth_subscribe                              |      -       |     not yet implemented (WebSockets only) |
| eth_unsubscribe                            |      -       |     not yet implemented (WebSockets only) |
|                                            |              |                                           |
| engine_newPayloadV1                        |     Yes      |                                           |
| engine_newPayloadV2                        |     Yes      |                                           |
| engine_forkchoiceUpdatedV1                 |     Yes      |                                           |
| engine_forkchoiceUpdatedV2                 |     Yes      |                                           |
| engine_getPayloadV1                        |     Yes      |                                           |
| engine_getPayloadV2                        |     Yes      |                                           |
| engine_exchangeCapabilities                |     Yes      |                                           |
| engine_exchangeTransitionConfigurationV1   |     Yes      |                                           |
|                                            |              |                                           |
| debug_accountRange                         |     Yes      |                                           |
| debug_accountAt                            |     Yes      |                                           |
| debug_getModifiedAccountsByHash            |     Yes      |                                           |
| debug_getModifiedAccountsByNumber          |     Yes      |                                           |
| debug_getBadBlocks                         |      No      |                        data not available |
| debug_getRawBlock                          |     Yes      |     can be optimized to avoid re-encoding |
| debug_getRawHeader                         |     Yes      |                                           |
| debug_getRawReceipts                       |      No      |                  see eth_getBlockReceipts |
| debug_getRawTransaction                    |     Yes      |                                           |
| debug_storageRangeAt                       |     Yes      |                                           |
| debug_traceBlockByHash                     |     Yes      |                       uses JSON streaming |
| debug_traceBlockByNumber                   |     Yes      |                       uses JSON streaming |
| debug_traceTransaction                     |     Yes      |                       uses JSON streaming |
| debug_traceCall                            |     Yes      |                       uses JSON streaming |
| debug_traceCallMany                        |     Yes      |                       uses JSON streaming |
|                                            |              |                                           |
| trace_call                                 |     Yes      |                                           |
| trace_callMany                             |     Yes      |                                           |
| trace_rawTransaction                       |     Yes      |                                           |
| trace_replayBlockTransactions              |     Yes      |                                           |
| trace_replayTransaction                    |     Yes      |                                           |
| trace_block                                |     Yes      |                                           |
| trace_filter                               |     Yes      |                       uses JSON streaming |
| trace_get                                  |     Yes      |                                           |
| trace_transaction                          |     Yes      |                                           |
|                                            |              |                                           |
| txpool_content                             |     Yes      |                                           |
| txpool_status                              |     Yes      |                                           |
|                                            |              |                                           |
| eth_getCompilers                           |      No      |                                deprecated |
| eth_compileLLL                             |      No      |                                deprecated |
| eth_compileSolidity                        |      No      |                                deprecated |
| eth_compileSerpent                         |      No      |                                deprecated |
|                                            |              |                                           |
| db_putString                               |      No      |                                deprecated |
| db_getString                               |      No      |                                deprecated |
| db_putHex                                  |      No      |                                deprecated |
| db_getHex                                  |      No      |                                deprecated |
|                                            |              |                                           |
| shh_post                                   |      No      |                                deprecated |
| shh_version                                |      No      |                                deprecated |
| shh_newIdentity                            |      No      |                                deprecated |
| shh_hasIdentity                            |      No      |                                deprecated |
| shh_newGroup                               |      No      |                                deprecated |
| shh_addToGroup                             |      No      |                                deprecated |
| shh_newFilter                              |      No      |                                deprecated |
| shh_uninstallFilter                        |      No      |                                deprecated |
| shh_getFilterChanges                       |      No      |                                deprecated |
| shh_getMessages                            |      No      |                                deprecated |
|                                            |              |                                           |
| erigon_cumulativeChainTraffic              |     Yes      |                                           |
| erigon_getHeaderByHash                     |     Yes      |                                           |
| erigon_getHeaderByNumber                   |     Yes      |                                           |
| erigon_getBalanceChangesInBlock            |     Yes      |                                           |
| erigon_getBlockByTimestamp                 |     Yes      |                                           |
| erigon_getBlockReceiptsByBlockHash         |     Yes      |                                           |
| erigon_getLogsByHash                       |     Yes      |                                           |
| erigon_forks                               |     Yes      |                                           |
| erigon_watchTheBurn                        |     Yes      |                                           |
| erigon_nodeInfo                            |     Yes      |                                           |
| erigon_blockNumber                         |     Yes      |                                           |
| erigon_cacheCheck                          |      -       |                       not yet implemented |
| erigon_getLatestLogs                       |     Yes      |                                           |
|                                            |              |                                           |
| bor_getSnapshot                            |      -       |                       not yet implemented |
| bor_getAuthor                              |      -       |                       not yet implemented |
| bor_getSnapshotAtHash                      |      -       |                       not yet implemented |
| bor_getSigners                             |      -       |                       not yet implemented |
| bor_getSignersAtHash                       |      -       |                       not yet implemented |
| bor_getCurrentProposer                     |      -       |                       not yet implemented |
| bor_getCurrentValidators                   |      -       |                       not yet implemented |
| bor_getRootHash                            |      -       |                       not yet implemented |
|                                            |              |                                           |
| parity_getBlockReceipts                    |     Yes      |              same as eth_getBlockReceipts |
| parity_listStorageKeys                     |     Yes      |                                           |
|                                            |              |                                           |
| ots_getApiLevel                            |     Yes      |                                           |
| ots_getInternalOperations                  |     Yes      |                                           |
| ots_searchTransactionsBefore               |     Yes      |                                           |
| ots_searchTransactionsAfter                |     Yes      |                                           |
| ots_getBlockDetails                        |     Yes      |                                           |
| ots_getBlockDetailsByHash                  |     Yes      |                                           |
| ots_getBlockTransactions                   |     Yes      |                                           |
| ots_hasCode                                |     Yes      |                                           |
| ots_traceTransaction                       |     Yes      |                                           |
| ots_getTransactionError                    |     Yes      |                                           |
| ots_getTransactionBySenderAndNonce         |     Yes      |                                           |
| ots_getContractCreator                     |     Yes      |                                           |

This table is constantly updated. Please visit again.
