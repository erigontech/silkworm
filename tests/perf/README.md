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

* Erigon RPCDaemon commit: https://github.com/ledgerwatch/erigon/commit/29fa1aa35aee589c3a27b6976a04ee53b6c1c354
* Silkrpc commit: https://github.com/torquem-ch/silkrpc/commit/54bef99171b2336a1b2451cd29be6a79629d61b9

## Build
Follow the instructions for building:

* Erigon RPCDaemon [build](https://github.com/)
* Silkrpc [build](https://github.com/torquem-ch/silkrpc/tree/eth_get_logs#linux--macos)

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
Automatically activated by the performance test script.
#### _Silkrpc_
Automatically activated by the performance test script.

### 1.2 Test Workload

Currently the performance workload targets just the [eth_getLogs](https://eth.wiki/json-rpc/API#eth_getlogs) Ethereum API. The test workloads are executed using requests files of [Vegeta](https://github.com/tsenart/vegeta/), a HTTP load testing tool.

#### _Workload Generation_

Execute Erigon [bench8 tool](https://github.com/ledgerwatch/erigon/blob/3388c1f1af6c65808830e5839a0c6d5d78f018fa/cmd/rpctest/rpctest/bench8.go) against both Erigon RPCDaemon and Silkrpc using the following command line:

```
build/bin/rpctest bench8 --erigonUrl http://localhost:8545 --gethUrl http://localhost:51515 --needCompare --block 200000
```

Vegeta request files are written to `/tmp/erigon_stress_test`:
* results_geth_debug_getModifiedAccountsByNumber.csv, results_geth_eth_getLogs.csv
* results_turbo_geth_debug_getModifiedAccountsByNumber.csv, results_turbo_geth_eth_getLogs.csv
* vegeta_geth_debug_getModifiedAccountsByNumber.txt, vegeta_geth_eth_getLogs.txt
* vegeta_turbo_geth_debug_getModifiedAccountsByNumber.txt, vegeta_turbo_geth_eth_getLogs.txt

#### _Workload Activation_

From Silkrpc project directory check the performance test runner usage:
```
$ tests/perf/run_perf_tests.py
Usage: ./run_perf_tests.py -h -p vegetaPatternTarFile -c daemonOnCore  -t erigonAddress -g erigonBuildDir -s silkrpcBuildDir -r testRepetitions - t testSequence

Launch an automated performance test sequence on Silkrpc and RPCDaemon using Vegeta

-h                      print this help
-d rpcDaemonAddress     address of daemon eg (10.1.1.20)                                                       [default: localhost]
-p vegetaPatternTarFile path to the request file for Vegeta attack                                             [default: ./vegeta/erigon_stress_test_001.tar]
-c daemonVegetaOnCore   cpu list in taskset format for daemon & vegeta (e.g. 0-1:2-3 or 0-2:3-4 or 0,2:3,4...) [default: -:-]
-a erigonAddress        address of ERIGON Core component as <address>:<port> (e.g. localhost:9090)             [default: localhost:9090]
-g erigonBuildDir       path to ERIGON build folder (e.g. ../../../erigon/build)                               [default: ../../../erigon/build/]
-s silkrpcBuildDir      path to Silkrpc build folder (e.g. ../../build_gcc_release/)                           [default: ../../build_gcc_release/]
-r testRepetitions      number of repetitions for each element in test sequence (e.g. 10)                      [default: 10]
-t testSequence         list of query-per-sec and duration tests as <qps1>:<t1>,... (e.g. 200:30,400:10)       [default: 50:30,200:30,200:60,400:30,600:60]
-n numContexts          number of Silkrpc execution contexts (i.e. 1+1 asio+grpc threads)                      [default: 6]
-m mode                 tests type silkrpc(1), rpcdaemon(2) and both (3) (i.e. 3)                              [default: 3]
```
Results are written in a CSV file `/tmp/<date_time>_perf.csv`.

So for example:
```
tests/perf/run_perf_tests.py 
```

## 2. Manual Setup

These are the instructions to execute *manually* the performance comparison tests.

### 2.1 Activation

The command lines to activate such components for performance testing are listed below (you can also experiment allocating a different number of cores or removing `taskset`).

#### _Erigon Core_
From Erigon project directory:
```
build/bin/erigon --goerli --private.api.addr=localhost:9090
```
#### _Erigon RPCDaemon_
From Erigon project directory:
```
taskset -c 0-1 build/bin/rpcdaemon --private.api.addr=localhost:9090 --http.api=eth,debug,net,web3
```
RPCDaemon will be running on port 8545
#### _Silkrpc_
From Silkrpc project directory:
```
taskset -c 0-1 build_gcc_release/cmd/silkrpcdaemon --target localhost:9090
```
Silkrpc will be running on port 51515

### 2.2 Test Workload

Currently the performance workload targets just the [eth_getLogs](https://eth.wiki/json-rpc/API#eth_getlogs) Ethereum API. The test workloads are executed using requests files of [Vegeta](https://github.com/tsenart/vegeta/), a HTTP load testing tool.

#### _Workload Generation_

Execute Erigon [bench8 tool](https://github.com/ledgerwatch/erigon/blob/3388c1f1af6c65808830e5839a0c6d5d78f018fa/cmd/rpctest/rpctest/bench8.go) against both Erigon RPCDaemon and Silkrpc using the following command line:

```
build/bin/rpctest bench8 --erigonUrl http://localhost:8545 --gethUrl http://localhost:51515 --needCompare --block 200000
```

Vegeta request files are written to `/tmp/erigon_stress_test`:
* results_geth_debug_getModifiedAccountsByNumber.csv, results_geth_eth_getLogs.csv
* results_turbo_geth_debug_getModifiedAccountsByNumber.csv, results_turbo_geth_eth_getLogs.csv
* vegeta_geth_debug_getModifiedAccountsByNumber.txt, vegeta_geth_eth_getLogs.txt
* vegeta_turbo_geth_debug_getModifiedAccountsByNumber.txt, vegeta_turbo_geth_eth_getLogs.txt

#### _Workload Activation_

From Silkrpc project directory execute the Vegeta attack using the scripts in [tests/perf](https://github.com/torquem-ch/silkrpc/tree/072dbc0314f383fbe236fc0c26e34187fe2191ca/tests/perf):
```
tests/perf/vegeta_attack_getLogs_rpcdaemon.sh [rate] [duration]
tests/perf/vegeta_attack_getLogs_silkrpc.sh [rate] [duration]
```
where `[rate]` indicates the target query-per-seconds during the attack (optional, default: 200) and `[duration]` is the duration in seconds of the attack (optional, default: 30)

Vegeta reports in text format are written to the working directory.
