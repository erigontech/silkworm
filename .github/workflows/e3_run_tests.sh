:
#python3 ./run_tests.py --continue --blockchain mainnet --jwt $1 --display-only-fail --port 8545 -x admin_,eth_mining,eth_getWork,eth_coinbase,eth_createAccessList/test_16.json,engine_,net_,web3_,txpool_,eth_submitWork,eth_submitHashrate,eth_protocolVersion,erigon_nodeInfo,debug_accountRange,debug_getModifiedAccounts,debug_storageRangeAt,erigon_getBalanceChangesInBlock,ots_getTransactionBySenderAndNonce,parity_listStorageKeys,ots_getContractCreator,erigon_getLatestLogs,eth_getLogs,erigon_getBlockReceiptsByBlockHash,parity_getBlockReceipts,eth_getTransactionReceipt,ots_getBlockDetails,ots_getBlockDetailsByHash,ots_getBlockTransactions,erigon_getLogsByHash,eth_feeHistory,eth_getBlockReceipts,ots_searchTransactionsAfter,ots_searchTransactionsBefore --transport_type http,websocket

python3 ./run_tests.py --continue --blockchain mainnet --jwt $1 --display-only-fail --port 8545 -x admin_,eth_mining,\
eth_getWork,eth_coinbase,\
eth_createAccessList/test_16.json,\
engine_,\
net_,\
web3_,\
txpool_,\
eth_submitWork,\
eth_submitHashrate,\
eth_protocolVersion,\
erigon_nodeInfo,\
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
erigon_getBalanceChangesInBlock,\
ots_getTransactionBySenderAndNonce,\
parity_listStorageKeys,\
ots_getContractCreator,\
erigon_getLatestLogs,\
eth_getLogs,\
erigon_getBlockReceiptsByBlockHash,\
parity_getBlockReceipts,\
eth_getTransactionReceipt,\
ots_getBlockDetails,\
ots_getBlockDetailsByHash,\
ots_getBlockTransactions,\
erigon_getLogsByHash,\
eth_feeHistory,\
eth_getBlockReceipts,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore --transport_type http,websocket
exit $?
