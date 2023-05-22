# Requirements

```
pip3 install -r requirements.txt
```

Currently, `json-diff` is also required:

```
sudo apt update
sudo apt install npm
npm install -g json-diff
```

# Integration test (17/04/23)

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex

```
Test time-elapsed (secs):     74
Number of executed tests:     389/389
Number of NOT executed tests: 0
Number of success tests:      389
Number of failed tests:       0

```


### To run integration tests comparing results with RPCdaemon response: ./run_tests.py -d -c -k jwt.hex
```
010. debug_traceBlockByHash/test_02.tar                           Skipped
011. debug_traceBlockByHash/test_03.tar                           Skipped
012. debug_traceBlockByHash/test_04.tar                           Skipped
014. debug_traceBlockByNumber/test_02.tar                         Skipped
031. debug_traceCall/test_10.json                                 Skipped
035. debug_traceCall/test_14.json                                 Skipped
038. debug_traceCall/test_17.json                                 Skipped
054. engine_exchangeCapabilities/test_1.json                      Failed
076. erigon_watchTheBurn/test_1.json                              Skipped
108. eth_feeHistory/test_1.json                                   Skipped
197. eth_maxPriorityFeePerGas/test_1.json                         Skipped
222. parity_getBlockReceipts/test_1.json                          Skipped
322. trace_rawTransaction/test_01.json                            Skipped
385. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     98
Number of executed tests:     376/389
Number of NOT executed tests: 13
Number of success tests:      375
Number of failed tests:       1
```

### To run integration tests comparing results with local DB: ./run_tests.py -d -c -k jwt.hex

```
010. debug_traceBlockByHash/test_02.tar                           Skipped
011. debug_traceBlockByHash/test_03.tar                           Skipped
012. debug_traceBlockByHash/test_04.tar                           Skipped
014. debug_traceBlockByNumber/test_02.tar                         Skipped
031. debug_traceCall/test_10.json                                 Skipped
035. debug_traceCall/test_14.json                                 Skipped
038. debug_traceCall/test_17.json                                 Skipped
054. engine_exchangeCapabilities/test_1.json                      Failed
076. erigon_watchTheBurn/test_1.json                              Skipped
108. eth_feeHistory/test_1.json                                   Skipped
197. eth_maxPriorityFeePerGas/test_1.json                         Skipped
222. parity_getBlockReceipts/test_1.json                          Skipped
322. trace_rawTransaction/test_01.json                            Skipped
385. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     99
Number of executed tests:     376/389
Number of NOT executed tests: 13
Number of success tests:      375
Number of failed tests:       1

```


