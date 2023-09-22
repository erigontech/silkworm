# Performance Tests
These are the instructions to execute the performance comparison tests between Silkrpc and Erigon RPCDaemon.

## System Configuration
The following system configuration steps shall be performed:

* increase core dump size 
```
ulimit -c unlimited
```
* increase max file descriptors
```
ulimit -n 999999
```
* check current IP local port range and increase it (writing permanently in /etc/sysctl.conf)
```
cat /proc/sys/net/ipv4/ip_local_port_range
sudo sysctl -w "net.ipv4.ip_local_port_range=5000 65000"
```

## Software Versions
In order to reproduce the environment used in last performance testing session, pick the following source code versions:

* Erigon RPCDaemon commit:  https://github.com/ledgerwatch/erigon/releases/tag/v2.48.1
* Silkrpc commit: https://github.com/erigontech/silkworm

## Build
Follow the instructions for building:

* Erigon RPCDaemon [build](https://github.com/)
* Silkrpc [build](https://github.com/torquem-ch/silkworm)

## 1. Automated Setup
These are the instructions to execute *automatically* the performance comparison tests.

### 1.1 Activation
The command lines to activate such Erigon Core for performance testing are

#### _Erigon Core_
From Erigon project directory:
```
build/bin/erigon --goerli --private.api.addr=localhost:9090
```
#### _Erigon RPCDaemon_
./build/bin/rpcdaemon --private.api.addr=localhost:9090 --http.api=eth,debug,net,web3,txpool,trace,erigon,parity,ots  --datadir < select erigon db>

#### _Silkrpc_
./build/cmd/silkrpcdaemon --private.addr 127.0.0.1:9090 --eth.addr 127.0.0.1:51515 --engine.addr 127.0.0.1:51516 --workers 64 --contexts 8 --datadir <select erigon db>  --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity 2 

### 1.2 Test Workload

Currently the performance workload targets just the [eth_getLogs, eth_call, eth_getBalance] Ethereum API. The test workloads are executed using requests files of [Vegeta](https://github.com/tsenart/vegeta/), a HTTP load testing tool.

#### _Workload Generation_

Execute Erigon [bench<api name> tool](https://github.com/ledgerwatch/erigon/blob/3388c1f1af6c65808830e5839a0c6d5d78f018fa/cmd/rpctest/rpctest/bench*.go) against both Erigon RPCDaemon and Silkrpc using the following command line:

```
build/bin/rpctest bench<api name> --erigonUrl http://localhost:8545 --gethUrl http://localhost:51515 --blockFrom 200000 --blockTo 300000
```

Vegeta request files are written to `/tmp/erigon_stress_test`:
* results_geth_debug_getModifiedAccountsByNumber.csv, results_geth_eth_<api>.csv
* results_turbo_geth_debug_getModifiedAccountsByNumber.csv, results_turbo_geth_<api>.csv
* vegeta_geth_debug_getModifiedAccountsByNumber.txt, vegeta_geth_eth_<api>.txt
* vegeta_turbo_geth_debug_getModifiedAccountsByNumber.txt, vegeta_turbo_geth_eth_<api>.txt

#### _Workload Activation_

From Silkrpc project directory check the performance test runner usage:
```
$ tests/perf/run_perf_tests.py
Usage: ./run_perf_tests.py -p vegetaPatternTarFile -y <api_name>  

Launch an automated performance test sequence on Silkrpc and RPCDaemon using Vegeta

-h                      print this help
-Z                      doen't verify server is still active
-R                      generate Report
-u                      save test report in Git repo
-v                      verbose
-x                      verbose and tracing
-y testType             test type: eth_call, eth_getLogs                                                       [default: eth_getLogs]
-m targetMode           target mode: silkrpc(1), rpcdaemon(2), both(3)                                         [default: 3]
-p vegetaPatternTarFile path to the request file for Vegeta attack                                             [default: ./vegeta/erigon_stress_test_eth_getLogs_goerly_001.tar]
-r testRepetitions      number of repetitions for each element in test sequence (e.g. 10)                      [default: 10]
-t testSequence         list of query-per-sec and duration tests as <qps1>:<t1>,... (e.g. 200:30,400:10)       [default: 50:30,1000:30,2500:20,10000:20]
-w testWaitInterval     time interval between successive test iterations in sec                                [default: 5]
-d rpcDaemonAddress     Erigon: address of RPCDaemon (e.g. 10.1.1.20)                                          [default: localhost]
-a erigonAddress        Erigon: address of Core component as <address>:<port> (e.g. localhost:9090)            [default: localhost:9090]
-g erigonBuildDir       Erigon: path to build folder (e.g. ../../../erigon/build)                              [default: ../../../erigon/build/]
-s silkrpcBuildDir      Silkrpc: path to build folder (e.g. ../../build/)                                      [default: ../../build/]
-c daemonVegetaOnCore   cpu list in taskset format for daemon & vegeta (e.g. 0-1:2-3 or 0-2:3-4 or 0,2:3,4...) [default: -:-]


```
Results are written in a CSV file `/tmp/<date_time>_perf.csv`.

