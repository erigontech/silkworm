#!/usr/bin/env python3
""" Stress the unit test suite on multiple compiler + build configurations
"""

from enum import Enum
import getopt
import os
import sys
from typing import List


class UnitTestModule(str, Enum):
    """ The unit test modules"""
    core_test = 'core_test'
    node_test = 'node_test'
    rpcdaemon_test = 'rpcdaemon_test'
    sentry_test = 'sentry_test'
    sync_test = 'sync_test'

    @classmethod
    def item_names(cls) -> List[str]:
        """ Return the list of enumeration item names """
        return [member_name for member_name in UnitTestModule.__members__.keys()]

    @classmethod
    def has_item(cls, name: str) -> bool:
        """ Return true if name is a valid enumeration item, false otherwise """
        return name in cls.item_names()


class UnitTest:
    """ The unit test executable """

    def __init__(self, module: UnitTestModule, build_dir: str):
        """ Create a new unit test execution """
        self.module = module
        self.build_dir = build_dir

    def execute(self, num_iterations: int, test_name: str = None, test_options: str = "") -> None:
        """ Execute the unit tests `num_iterations` times """
        cmd = self.build_dir + "/cmd/test/" + self.module.name.lower()
        if test_name is not None and test_name != '':
            cmd = cmd + " \"" + test_name + "\""
        cmd = cmd + " " + test_options
        print("Unit test runner: " + cmd + "\n")

        print("Unit test stress for " + self.module.name.lower() + " STARTED")
        for i in range(num_iterations):
            print("Unit test stress for " + self.module.name.lower() + " RUN [i=" + str(i) + "]")
            status = os.system(cmd)
            if status != 0:
                print("Unit test stress for " + self.module.name.lower() + " FAILED [i=" + str(i) + "]")
                sys.exit(-1)
        print("Unit test stress for " + self.module.name.lower() + " COMPLETED [" + str(num_iterations) + "]")


DEFAULT_NUM_ITERATIONS: int = 1000
DEFAULT_MODULES: List[str] = UnitTestModule.item_names()


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
    print("-o\toptions")
    print("  \tthe Catch2 options to pass to the launcher enclosed in string (default: \"\" i.e. none)")
    print("-t\ttest")
    print("  \tthe name of the unique Catch2 TEST_CASE to execute (default: run all tests)")
    sys.exit(0)


def main(argv) -> int:
    """ Main entry point """
    opts, args = getopt.getopt(argv[1:], "hi:m:o:t:")

    if len(args) == 0:
        usage(argv)
        return 1

    build_dir = args[0]
    test_name = None
    test_options = ""
    iterations = DEFAULT_NUM_ITERATIONS
    modules = DEFAULT_MODULES

    for option, option_arg in opts:
        if option in ("-h", "--help"):
            usage(argv)
        elif option == "-i":
            iterations = int(option_arg)
        elif option == "-m":
            modules = str(option_arg).split(",")
        elif option == "-o":
            test_options = option_arg
            print("test_options=" + test_options)
        elif option == "-t":
            test_name = option_arg

    for module_name in modules:
        module_name = module_name.lower()
        if not UnitTestModule.has_item(module_name):
            print("Invalid test module name [" + module_name + "], ignored")
            continue
        unit_test_module = UnitTestModule(module_name)
        unit_test = UnitTest(unit_test_module, build_dir)
        unit_test.execute(iterations, test_name, test_options)

    return 0


#
# module as main
#
if __name__ == "__main__":
    exit_code = main(sys.argv)
    sys.exit(exit_code)
