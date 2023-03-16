#!/usr/bin/env python3
""" Stress the unit test suite on multiple compiler + build configurations
"""

from enum import Enum
import getopt
import os
import sys
from typing import Dict, List


class UnitTestModule(str, Enum):
    """ The unit test modules"""
    CORE_TEST = 'CORE_TEST'
    NODE_TEST = 'NODE_TEST'
    RPCDAEMON_TEST = 'RPCDAEMON_TEST'
    SENTRY_TEST = 'SENTRY_TEST'
    SYNC_TEST = 'SYNC_TEST'

    @classmethod
    def has_item(cls, name: str) -> bool:
        """ Return true if name is a valid enumeration item, false otherwise """
        return name in UnitTestModule._member_names_ # pylint: disable=no-member


class UnitTest:
    """ The unit test executable """

    def __init__(self, module: UnitTestModule, build_dir: str):
        """ Create a new unit test execution """
        self.module = module
        self.build_dir = build_dir

    def execute(self, num_iterations: int, test_name: str = None) -> None:
        """ Execute the unit tests `num_iterations` times """
        cmd = self.build_dir + "/cmd/test/" + self.module.name.lower()
        if test_name is not None and test_name != '':
            cmd = cmd + " \"" + test_name + "\""
        cmd = cmd + " -d yes"
        print("Unit test runner: " + cmd + "\n")

        print("Unit test stress for " + self.module.name.lower() + " STARTED")
        for i in range(num_iterations):
            print("Unit test stress for " + self.module.name.lower() + " RUN [i=" + str(i) + "]")
            status = os.system(cmd)
            if status != 0:
                print("Unit test stress for " + self.module.name.lower() + " FAILED [i=" + str(i) + "]")
                sys.exit(-1)
        print("Unit test stress for " + self.module.name.lower() + " COMPLETED [" + str(num_iterations) + "]")


DEFAULT_TEST_NAME: str = None
DEFAULT_NUM_ITERATIONS: int = 1000
DEFAULT_MODULES: List[str] = [
    UnitTestModule.CORE_TEST,
    UnitTestModule.NODE_TEST,
    UnitTestModule.RPCDAEMON_TEST,
    UnitTestModule.SENTRY_TEST,
    UnitTestModule.SYNC_TEST
]


def usage(argv):
    """ Print usage """
    print("Usage: " + argv[0] + " [-h] [-i iterations] [-m modules] [-t test] builddir")
    print("")
    print("Launch an automated unit test sequence on target build configuration")
    print("")
    print("builddir")
    print("  \tthe path of the target build folder")
    print("")
    print("-h\tprint this help")
    print("-i\titerations")
    print("  \tthe number of iterations for each configuration (default: " + str(DEFAULT_NUM_ITERATIONS) + ")")
    print("-m\tmodules")
    print("  \tthe list of unit test modules to launch (default: " + str(DEFAULT_MODULES) + ")")
    print("-t\ttest")
    print("  \tthe name of the unique TEST to execute (default: run all tests)")
    sys.exit(0)


def main(argv) -> int:
    """ Main entry point """
    opts, args = getopt.getopt(argv[1:], "hi:m:t:")

    if len(args) == 0:
        usage(argv)
        return 1

    build_dir = args[0]
    test_name = DEFAULT_TEST_NAME
    iterations = DEFAULT_NUM_ITERATIONS
    modules = DEFAULT_MODULES

    for option, option_arg in opts:
        if option in ("-h", "--help"):
            usage(argv)
        elif option == "-i":
            iterations = int(option_arg)
        elif option == "-m":
            modules = str(option_arg).split(",")
        elif option == "-t":
            test_name = option_arg

    for module_name in modules:
        module_name = module_name.upper()
        if not UnitTestModule.has_item(module_name):
            print("Invalid test module name [" + module_name + "], ignored")
            continue
        unit_test_module = UnitTestModule(module_name)
        unit_test = UnitTest(unit_test_module, build_dir)
        unit_test.execute(iterations, test_name)

    return 0


#
# module as main
#
if __name__ == "__main__":
    exit_code = main(sys.argv)
    sys.exit(exit_code)
