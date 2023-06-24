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
Test time-elapsed (secs):     81
Number of executed tests:     410/410
Number of NOT executed tests: 0
Number of success tests:      410
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
058. engine_getPayloadBodiesByHashV1/test_1.json                  Skipped
060. engine_getPayloadBodiesByRangeV1/test_1.json                 Skipped
081. erigon_watchTheBurn/test_1.json                              Skipped
103. eth_callMany/test_01.json                                    Skipped
104. eth_callMany/test_02.json                                    Skipped
106. eth_callMany/test_04.json                                    Skipped
107. eth_callMany/test_05.json                                    Skipped
108. eth_callMany/test_06.json                                    Skipped
111. eth_callMany/test_09.json                                    Skipped
112. eth_callMany/test_10.json                                    Skipped
126. eth_feeHistory/test_1.json                                   Skipped
217. eth_maxPriorityFeePerGas/test_1.json                         Skipped
243. parity_getBlockReceipts/test_1.json                          Skipped
343. trace_rawTransaction/test_01.json                            Skipped
406. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     106
Number of executed tests:     388/410
Number of NOT executed tests: 22
Number of success tests:      388
Number of failed tests:       0

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
058. engine_getPayloadBodiesByHashV1/test_1.json                  Skipped
060. engine_getPayloadBodiesByRangeV1/test_1.json                 Skipped
081. erigon_watchTheBurn/test_1.json                              Skipped
103. eth_callMany/test_01.json                                    Skipped
104. eth_callMany/test_02.json                                    Skipped
106. eth_callMany/test_04.json                                    Skipped
107. eth_callMany/test_05.json                                    Skipped
108. eth_callMany/test_06.json                                    Skipped
111. eth_callMany/test_09.json                                    Skipped
112. eth_callMany/test_10.json                                    Skipped
126. eth_feeHistory/test_1.json                                   Skipped
217. eth_maxPriorityFeePerGas/test_1.json                         Skipped
243. parity_getBlockReceipts/test_1.json                          Skipped
343. trace_rawTransaction/test_01.json                            Skipped
406. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     97
Number of executed tests:     388/410
Number of NOT executed tests: 22
Number of success tests:      388
Number of failed tests:       0

```


