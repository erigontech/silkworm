# Integration Test Suite

These integration tests currently available for Goerli testnet must run as non-regression suite

# Requirements

```
% pip3 install -r requirements.txt
```

Currently, `json-diff` is also required:

```
% sudo apt update
% sudo apt install npm
% npm install -g json-diff
```

# Run tests

```
% python3 ./run_tests.py -c -k jwt.hex
```

# Synopsis

```
% python3 ./run_tests.py -h

Usage: ./run_tests.py:

Launch an automated test sequence on Silkworm RpcDaemon (aka Silkrpc) or Erigon RpcDaemon

-h print this help
-f shows only failed tests (not Skipped)
-c runs all tests even if one test fails [default: exit at first test fail]
-r connect to Erigon RpcDaemon [default: connect to Silkrpc] 
-l <number of loops>
-a <test_api>: run all tests of the specified API
-s <start_test_number>: run tests starting from input
-t <test_number>: run single test
-d send requests also to the reference daemon i.e. Erigon RpcDaemon
-i <infura_url> send any request also to the Infura API endpoint as reference
-b blockchain [default: goerly]
-v verbose
-o dump response
-k authentication token file
-x exclude API list (i.e txpool_content,txpool_status,engine_
-X exclude test list (i.e 18,22
-H host where the RpcDaemon is located (e.g. 10.10.2.3)
```

# Integration test (04/08/23)
# erigon/rpcdaemon version 2.42 

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex
### (in case Erigon without snapshot & KV access to DB)

```
119. eth_callBundle/test_9.json                                   Failed
259. ots_getInternalOperations/test_1.json                        Skipped
260. ots_getInternalOperations/test_2.json                        Skipped
                                                                                    
Test time-elapsed (secs):     78
Number of executed tests:     437/439
Number of NOT executed tests: 2
Number of success tests:      436
Number of failed tests:       1
```


### To run integration tests comparing results with RPCdaemon response (KV) : ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon without snapshot & KV access to DB comparing results with RPCDaemon KV)
```
119. eth_callBundle/test_9.json                                   Failed

Test time-elapsed (secs):     123
Number of executed tests:     437/439
Number of NOT executed tests: 2
Number of success tests:      436
Number of failed tests:       1
```

### To run integration tests comparing results with RPCdaemon response (KV) : ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon with snapshot & KV access to DB comparing results with RPCDaemon KV)
```
004. debug_accountRange/test_1.json                               Failed
088. erigon_cumulativeChainTraffic/test_1.json                    Failed
111. eth_callBundle/test_1.json                                   Failed
112. eth_callBundle/test_2.json                                   Failed
113. eth_callBundle/test_3.json                                   Failed
114. eth_callBundle/test_4.json                                   Failed
115. eth_callBundle/test_5.json                                   Failed
116. eth_callBundle/test_6.json                                   Failed
117. eth_callBundle/test_7.json                                   Failed
138. eth_createAccessList/test_4.json                             Failed
153. eth_getBlockByHash/test_4.json                               Failed
164. eth_getBlockByNumber/test_11.json                            Failed

Test time-elapsed (secs):     247
Number of executed tests:     437/439
Number of NOT executed tests: 2
Number of success tests:      425
Number of failed tests:       12
```


### To run integration tests comparing results with local DB: ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon without snapshot & local access to DB comparing results with RPCDaemon)
```
119. eth_callBundle/test_9.json                                   Failed

Test time-elapsed (secs):     109
Number of executed tests:     437/439
Number of NOT executed tests: 2
Number of success tests:      436
Number of failed tests:       1
```


