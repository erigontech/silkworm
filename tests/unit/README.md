# Unit Test Loop
This is a simple script to stress the unit test suite, useful when you need to debug some flaky unit test.
It works with multiple compilers and build configurations.

## Usage

```
$cd tests/unit

$./run_unit_test_loop.py
Usage: ./run_unit_test_loop.py [-h] [-i iterations] [-m modules] [-t test] builddir

Launch an automated unit test sequence on target build configuration

builddir
        the path of the target build folder

-h      print this help
-i      iterations
        the number of iterations for each configuration (default: 1000)
-m      modules
        the list of unit test modules to launch (default: ['core_test', 'node_test', 'rpcdaemon_test', 'sentry_test', 'sync_test'])
-o      options
        the Catch2 options to pass to the launcher enclosed in string (default: "" i.e. none)
-t      test
        the name of the unique Catch2 TEST_CASE to execute (default: run all tests)
```

## Examples

```
$cd tests/unit

$./run_unit_test_loop.py -i 100 -m node_test ../../cmake-build-clang-release

$./run_unit_test_loop.py -i 100 -m node_test -o "-d yes" ../../cmake-build-clang-release

$./run_unit_test_loop.py -i 100 -m node_test -t "MemoryMutationCursor: to_next" ../../cmake-build-clang-release
```