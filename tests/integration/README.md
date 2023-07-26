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

# Integration test (28/06/23)

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex

```
Test time-elapsed (secs):     69
Number of executed tests:     415/415
Number of NOT executed tests: 0
Number of success tests:      415
Number of failed tests:       0

```


### To run integration tests comparing results with RPCdaemon response (KV) : ./run_tests.py -d -c -k jwt.hex
```
010. debug_traceBlockByHash/test_02.tar                           Skipped
011. debug_traceBlockByHash/test_03.tar                           Skipped
012. debug_traceBlockByHash/test_04.tar                           Skipped
014. debug_traceBlockByNumber/test_02.tar                         Skipped
031. debug_traceCall/test_10.json                                 Skipped
035. debug_traceCall/test_14.json                                 Skipped
038. debug_traceCall/test_17.json                                 Skipped
063. engine_getPayloadBodiesByHashV1/test_1.json                  Skipped
065. engine_getPayloadBodiesByRangeV1/test_1.json                 Skipped
086. erigon_watchTheBurn/test_1.json                              Skipped
108. eth_callMany/test_01.json                                    Skipped
109. eth_callMany/test_02.json                                    Skipped
111. eth_callMany/test_04.json                                    Skipped
112. eth_callMany/test_05.json                                    Skipped
113. eth_callMany/test_06.json                                    Skipped
116. eth_callMany/test_09.json                                    Skipped
117. eth_callMany/test_10.json                                    Skipped
131. eth_feeHistory/test_1.json                                   Skipped
222. eth_maxPriorityFeePerGas/test_1.json                         Skipped
248. parity_getBlockReceipts/test_1.json                          Skipped
348. trace_rawTransaction/test_01.json                            Skipped
411. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     98
Number of executed tests:     393/415
Number of NOT executed tests: 22
Number of success tests:      393
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
063. engine_getPayloadBodiesByHashV1/test_1.json                  Skipped
065. engine_getPayloadBodiesByRangeV1/test_1.json                 Skipped
086. erigon_watchTheBurn/test_1.json                              Skipped
108. eth_callMany/test_01.json                                    Skipped
109. eth_callMany/test_02.json                                    Skipped
111. eth_callMany/test_04.json                                    Skipped
112. eth_callMany/test_05.json                                    Skipped
113. eth_callMany/test_06.json                                    Skipped
116. eth_callMany/test_09.json                                    Skipped
117. eth_callMany/test_10.json                                    Skipped
131. eth_feeHistory/test_1.json                                   Skipped
222. eth_maxPriorityFeePerGas/test_1.json                         Skipped
248. parity_getBlockReceipts/test_1.json                          Skipped
348. trace_rawTransaction/test_01.json                            Skipped
411. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     86
Number of executed tests:     393/415
Number of NOT executed tests: 22
Number of success tests:      393
Number of failed tests:       0


```


