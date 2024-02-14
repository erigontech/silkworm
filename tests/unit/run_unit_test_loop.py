#!/usr/bin/env python3
""" Stress the unit test suite on multiple compiler + build configurations
"""

from enum import Enum
import getopt
import os
import sys
from typing import List


class UnitTest:
    """ The unit test executable """

    def __init__(self, module: str):
        """ Create a new unit test execution """
        self.module = module

    def execute(self, num_iterations: int, test_name: str = None, test_options: str = "") -> None:
        """ Execute the unit tests `num_iterations` times """
        cmd = self.module
        if test_name is not None and test_name != '':
            cmd = cmd + " \"" + test_name + "\""
        cmd = cmd + " " + test_options
        print("Unit test runner: " + cmd + "\n")

        print("Unit test stress for " + self.module + " STARTED")
        for i in range(num_iterations):
            print("Unit test stress for " + self.module + " RUN [i=" + str(i) + "]")
            status = os.system(cmd)
            if status != 0:
                print("Unit test stress for " + self.module + " FAILED [i=" + str(i) + "]")
                sys.exit(-1)
        print("Unit test stress for " + self.module + " COMPLETED [" + str(num_iterations) + "]")


DEFAULT_NUM_ITERATIONS: int = 1000


def usage(argv):
    """ Print usage """
    print("Usage: " + argv[0] + " [-h] [-i iterations] [-t test] modules")
    print("")
    print("Launch an automated unit test sequence on target build configuration")
    print("")
    print("modules")
    print("  \tcomma-separated list of unit test executables to launch")
    print("")
    print("-h\tprint this help")
    print("-i\titerations")
    print("  \tthe number of iterations for each configuration (default: " + str(DEFAULT_NUM_ITERATIONS) + ")")
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

    modules = args[0].split(",")
    test_name = None
    test_options = ""
    iterations = DEFAULT_NUM_ITERATIONS

    for option, option_arg in opts:
        if option in ("-h", "--help"):
            usage(argv)
        elif option == "-i":
            iterations = int(option_arg)
        elif option == "-o":
            test_options = option_arg
            print("test_options=" + test_options)
        elif option == "-t":
            test_name = option_arg

    for module_name in modules:
        unit_test = UnitTest(module_name)
        unit_test.execute(iterations, test_name, test_options)

    return 0


#
# module as main
#
if __name__ == "__main__":
    exit_code = main(sys.argv)
    sys.exit(exit_code)
