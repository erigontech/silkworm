json-diff install:
------------------
- sudo apt update
- sudo apt install npm
- npm install -g json-diff
- pip install pyjwt


# Integration test (09/10)

### To run integration tests comparing results with json file: ./run_tests.py -c -k jwt.hex

```
Test time-elapsed (secs):     60
Number of executed tests:     371/371
Number of NOT executed tests: 0
Number of success tests:      371
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
204. parity_getBlockReceipts/test_1.json                          Skipped
304. trace_rawTransaction/test_01.json                            Skipped
367. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     75
Number of executed tests:     361/371
Number of NOT executed tests: 10
Number of success tests:      361
Number of failed tests:       0

```

#For local file ./run_tests.py -d -c -k jwt.hex 
008. debug_traceBlockByHash/test_02.tar                           Skipped
009. debug_traceBlockByHash/test_03.tar                           Skipped
010. debug_traceBlockByHash/test_04.tar                           Skipped
012. debug_traceBlockByNumber/test_02.tar                         Skipped
029. debug_traceCall/test_10.json                                 Skipped
033. debug_traceCall/test_14.json                                 Skipped
036. debug_traceCall/test_17.json                                 Skipped
204. parity_getBlockReceipts/test_1.json                          Skipped
304. trace_rawTransaction/test_01.json                            Skipped
367. txpool_content/test_1.json                                   Skipped
                                                                                    
Test time-elapsed (secs):     79
Number of executed tests:     361/371
Number of NOT executed tests: 10
Number of success tests:      361
Number of failed tests:       0

