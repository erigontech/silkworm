json-diff install:
------------------
- sudo apt update
- sudo apt install npm
- npm install -g json-diff
- pip install pyjwt


# Integration test (17/04/23)

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex

```
Test time-elapsed (secs):     65
Number of executed tests:     379/379
Number of NOT executed tests: 0
Number of success tests:      379
Number of failed tests:       0

```


### To run integration tests comparing results with RPCdaemon response: ./run_tests.py -d -c -k jwt.hex
```
008. debug_traceBlockByHash/test_02.tar                           Skipped
009. debug_traceBlockByHash/test_03.tar                           Skipped
010. debug_traceBlockByHash/test_04.tar                           Skipped
012. debug_traceBlockByNumber/test_02.tar                         Skipped
029. debug_traceCall/test_10.json                                 Skipped
033. debug_traceCall/test_14.json                                 Skipped
036. debug_traceCall/test_17.json                                 Skipped
065. erigon_forks/test_1.json                                     Failed
071. erigon_watchTheBurn/test_1.json                              Skipped
191. eth_maxPriorityFeePerGas/test_1.json                         Skipped
212. parity_getBlockReceipts/test_1.json                          Skipped
233. trace_call/test_04.json                                      Failed
240. trace_call/test_11.json                                      Failed
244. trace_call/test_15.json                                      Failed
246. trace_call/test_17.json                                      Failed
252. trace_callMany/test_04.json                                  Failed
253. trace_callMany/test_05.json                                  Failed
261. trace_callMany/test_13.json                                  Failed
262. trace_callMany/test_14.tar                                   Failed
263. trace_callMany/test_15.json                                  Failed
312. trace_rawTransaction/test_01.json                            Skipped
375. txpool_content/test_1.json                                   Skipped

```

#For local file ./run_tests.py -d -c -k jwt.hex 

```
008. debug_traceBlockByHash/test_02.tar                           Skipped
009. debug_traceBlockByHash/test_03.tar                           Skipped
010. debug_traceBlockByHash/test_04.tar                           Skipped
012. debug_traceBlockByNumber/test_02.tar                         Skipped
029. debug_traceCall/test_10.json                                 Skipped
033. debug_traceCall/test_14.json                                 Skipped
036. debug_traceCall/test_17.json                                 Skipped
065. erigon_forks/test_1.json                                     Failed
071. erigon_watchTheBurn/test_1.json                              Skipped
191. eth_maxPriorityFeePerGas/test_1.json                         Skipped
212. parity_getBlockReceipts/test_1.json                          Skipped
233. trace_call/test_04.json                                      Failed
240. trace_call/test_11.json                                      Failed
244. trace_call/test_15.json                                      Failed
246. trace_call/test_17.json                                      Failed
252. trace_callMany/test_04.json                                  Failed
253. trace_callMany/test_05.json                                  Failed
261. trace_callMany/test_13.json                                  Failed
262. trace_callMany/test_14.tar                                   Failed
263. trace_callMany/test_15.json                                  Failed
312. trace_rawTransaction/test_01.json                            Skipped
375. txpool_content/test_1.json                                   Skipped

```


