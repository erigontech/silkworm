# Unit Test Loop
This is a simple script to stress the unit test suite, useful when you need to debug some flaky unit test.
It works with multiple compilers and build configurations.

## Usage

```
$cd tests/unit

$./run_unit_test_loop.py
Usage: ./run_unit_test_loop.py [-h] [-i iterations] [-t test] modules

Launch an automated unit test sequence on target build configuration

modules
        comma-separated list of unit test executables to launch

-h      print this help
-i      iterations
        the number of iterations for each configuration (default: 1000)
-o      options
        the Catch2 options to pass to the launcher enclosed in string (default: "" i.e. none)
-t      test
        the name of the unique Catch2 TEST_CASE to execute (default: run all tests)
```

## Examples

```
$./run_unit_test_loop.py -i 100 build/silkworm/node/silkworm_node_test

$./run_unit_test_loop.py -i 100 -o "-d yes" build/silkworm/node/silkworm_node_test

$./run_unit_test_loop.py -i 100 -t "MemoryMutationCursor: to_next" build/silkworm/node/silkworm_node_test
```
