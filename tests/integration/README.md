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

# Integration test (11/08/23)
# erigon/rpcdaemon version 2.48.1 

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex
### (in case Erigon without snapshot & KV access to DB & Rpcdaemon embedded)

```
Test time-elapsed (secs):     77
Number of executed tests:     448/450
Number of NOT executed tests: 0
Number of success tests:      448
Number of failed tests:       0
```


### To run integration tests comparing results with RPCdaemon response (KV) : ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon without snapshot & KV access to DB comparing results with RPCDaemon KV, Rpcdaemon embedded)
```
091. erigon_forks/test_1.json                                     Failed
298. trace_block/test_01.tar                                      Failed
299. trace_block/test_02.tar                                      Failed
300. trace_block/test_03.tar                                      Failed
301. trace_block/test_04.tar                                      Failed
302. trace_block/test_05.tar                                      Failed
303. trace_block/test_06.tar                                      Failed
304. trace_block/test_07.tar                                      Failed
305. trace_block/test_08.json                                     Failed
306. trace_block/test_09.tar                                      Failed
307. trace_block/test_10.json                                     Failed
308. trace_block/test_11.json                                     Failed
309. trace_block/test_12.json                                     Failed
310. trace_block/test_13.json                                     Failed
311. trace_block/test_14.json                                     Failed
346. trace_filter/test_1.tar                                      Failed
347. trace_filter/test_2.tar                                      Failed
350. trace_filter/test_5.tar                                      Failed
351. trace_filter/test_6.tar                                      Failed
352. trace_filter/test_7.tar                                      Failed
                                                                                    
Test time-elapsed (secs):     112
Number of executed tests:     422/461
Number of NOT executed tests: 0
Number of success tests:      402
Number of failed tests:       20

```

### To run integration tests comparing results with RPCdaemon response (KV) : ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon with snapshot & KV access to DB comparing results with RPCDaemon KV & Rpcdaemon embedded)
```
091. erigon_forks/test_1.json                                     Failed
133. eth_callBundle/test_1.json                                   Failed
134. eth_callBundle/test_2.json                                   Failed
135. eth_callBundle/test_3.json                                   Failed
136. eth_callBundle/test_4.json                                   Failed
137. eth_callBundle/test_5.json                                   Failed
138. eth_callBundle/test_6.json                                   Failed
139. eth_callBundle/test_7.json                                   Failed
298. trace_block/test_01.tar                                      Failed
299. trace_block/test_02.tar                                      Failed
300. trace_block/test_03.tar                                      Failed
301. trace_block/test_04.tar                                      Failed
302. trace_block/test_05.tar                                      Failed
303. trace_block/test_06.tar                                      Failed
304. trace_block/test_07.tar                                      Failed
305. trace_block/test_08.json                                     Failed
306. trace_block/test_09.tar                                      Failed
307. trace_block/test_10.json                                     Failed
308. trace_block/test_11.json                                     Failed
309. trace_block/test_12.json                                     Failed
310. trace_block/test_13.json                                     Failed
311. trace_block/test_14.json                                     Failed
346. trace_filter/test_1.tar                                      Failed
347. trace_filter/test_2.tar                                      Failed
350. trace_filter/test_5.tar                                      Failed
351. trace_filter/test_6.tar                                      Failed
352. trace_filter/test_7.tar                                      Failed
                                                                                    
Test time-elapsed (secs):     119
Number of executed tests:     422/461
Number of NOT executed tests: 0
Number of success tests:      395
Number of failed tests:       27

```


### To run integration tests comparing results with local DB: ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon without snapshot & local access to DB comparing results with RPCDaemon)
```
091. erigon_forks/test_1.json                                     Failed
298. trace_block/test_01.tar                                      Failed
299. trace_block/test_02.tar                                      Failed
300. trace_block/test_03.tar                                      Failed
301. trace_block/test_04.tar                                      Failed
302. trace_block/test_05.tar                                      Failed
303. trace_block/test_06.tar                                      Failed
304. trace_block/test_07.tar                                      Failed
305. trace_block/test_08.json                                     Failed
306. trace_block/test_09.tar                                      Failed
307. trace_block/test_10.json                                     Failed
308. trace_block/test_11.json                                     Failed
309. trace_block/test_12.json                                     Failed
310. trace_block/test_13.json                                     Failed
311. trace_block/test_14.json                                     Failed
346. trace_filter/test_1.tar                                      Failed
347. trace_filter/test_2.tar                                      Failed
350. trace_filter/test_5.tar                                      Failed
351. trace_filter/test_6.tar                                      Failed
352. trace_filter/test_7.tar                                      Failed
                                                                                    
Test time-elapsed (secs):     106
Number of executed tests:     422/461
Number of NOT executed tests: 0
Number of success tests:      402
Number of failed tests:       20

```


### To run integration tests comparing results with local DB: ./run_tests.py -f -d -c -k jwt.hex
### (in case Erigon with snapshot & local access to DB comparing results with RPCDaemon)
```
091. erigon_forks/test_1.json                                     Failed
133. eth_callBundle/test_1.json                                   Failed
134. eth_callBundle/test_2.json                                   Failed
135. eth_callBundle/test_3.json                                   Failed
136. eth_callBundle/test_4.json                                   Failed
137. eth_callBundle/test_5.json                                   Failed
138. eth_callBundle/test_6.json                                   Failed
139. eth_callBundle/test_7.json                                   Failed
298. trace_block/test_01.tar                                      Failed
299. trace_block/test_02.tar                                      Failed
300. trace_block/test_03.tar                                      Failed
301. trace_block/test_04.tar                                      Failed
302. trace_block/test_05.tar                                      Failed
303. trace_block/test_06.tar                                      Failed
304. trace_block/test_07.tar                                      Failed
305. trace_block/test_08.json                                     Failed
306. trace_block/test_09.tar                                      Failed
307. trace_block/test_10.json                                     Failed
308. trace_block/test_11.json                                     Failed
309. trace_block/test_12.json                                     Failed
310. trace_block/test_13.json                                     Failed
311. trace_block/test_14.json                                     Failed
346. trace_filter/test_1.tar                                      Failed
347. trace_filter/test_2.tar                                      Failed
350. trace_filter/test_5.tar                                      Failed
351. trace_filter/test_6.tar                                      Failed
352. trace_filter/test_7.tar                                      Failed
                                                                                    
Test time-elapsed (secs):     98
Number of executed tests:     422/461
Number of NOT executed tests: 0
Number of success tests:      395
Number of failed tests:       27

```
