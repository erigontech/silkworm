#!/usr/bin/env python3
""" This script uses Vegeta to execute a list of performance tests (configured via command line) and saves its result in CSV file
"""

# pylint: disable=consider-using-with

import os
import csv
import pathlib
import sys
import time
import getopt
from datetime import datetime

import psutil

DEFAULT_TEST_SEQUENCE = "50:30,200:30,500:30,700:30,1000:30,1500:30,1700:30,2000:30"
DEFAULT_REPETITIONS = 10
DEFAULT_VEGETA_PATTERN_TAR_FILE = "./vegeta/erigon_stress_test_eth_getLogs_goerly_001.tar"
DEFAULT_DAEMON_VEGETA_ON_CORE = "-:-"
DEFAULT_ERIGON_ADDRESS = "localhost:9090"
DEFAULT_ERIGON_BUILD_DIR = "../../../erigon/build/"
DEFAULT_SILKRPC_BUILD_DIR = "../../build_gcc_release/"
DEFAULT_SILKRPC_NUM_CONTEXTS = ""
DEFAULT_RPCDAEMON_ADDRESS = "localhost"
DEFAULT_TEST_MODE = "3"
DEFAULT_WAITING_TIME = 5
DEFAULT_TEST_TYPE = "eth_getLogs"
DEFAULT_WAIT_MODE = "blocking"
DEFAULT_WORKERS = "16"

VEGETA_PATTERN_DIRNAME = "erigon_stress_test"
VEGETA_REPORT = "vegeta_report.hrd"
VEGETA_TAR_FILE_NAME = "vegeta_TAR_File"
VEGETA_PATTERN_SILKRPC_BASE = "/tmp/" + VEGETA_PATTERN_DIRNAME + "/vegeta_geth_"
VEGETA_PATTERN_RPCDAEMON_BASE = "/tmp/" + VEGETA_PATTERN_DIRNAME + "/vegeta_erigon_"

def usage(argv):
    """ Print script usage """
    print("Usage: " + argv[0] + " [options]")
    print("")
    print("Launch an automated performance test sequence on Silkrpc and RPCDaemon using Vegeta")
    print("")
    print("-h                      print this help")
    print("-D                      perf command")
    print("-z                      do not start server")
    print("-Z                      doen't verify server is still active")
    print("-u                      save test report in Git repo")
    print("-v                      verbose")
    print("-x                      verbose and tracing")
    print("-y testType             test type: eth_call, eth_getLogs                                                       [default: " + DEFAULT_TEST_TYPE + "]")
    print("-m targetMode           target mode: silkrpc(1), rpcdaemon(2), both(3)                                         [default: " + str(DEFAULT_TEST_MODE) + "]")
    print("-d rpcDaemonAddress     Erigon: address of RPCDaemon (e.g. 10.1.1.20)                                          [default: " + DEFAULT_RPCDAEMON_ADDRESS +"]")
    print("-p vegetaPatternTarFile path to the request file for Vegeta attack                                             [default: " + DEFAULT_VEGETA_PATTERN_TAR_FILE +"]")
    print("-c daemonVegetaOnCore   cpu list in taskset format for daemon & vegeta (e.g. 0-1:2-3 or 0-2:3-4 or 0,2:3,4...) [default: " + DEFAULT_DAEMON_VEGETA_ON_CORE +"]")
    print("-a erigonAddress        Erigon: address of Core component as <address>:<port> (e.g. localhost:9090)            [default: " + DEFAULT_ERIGON_ADDRESS + "]")
    print("-g erigonBuildDir       Erigon: path to build folder (e.g. ../../../erigon/build)                              [default: " + DEFAULT_ERIGON_BUILD_DIR + "]")
    print("-s silkrpcBuildDir      Silkrpc: path to build folder (e.g. ../../build_gcc_release/)                          [default: " + DEFAULT_SILKRPC_BUILD_DIR + "]")
    print("-r testRepetitions      number of repetitions for each element in test sequence (e.g. 10)                      [default: " + str(DEFAULT_REPETITIONS) + "]")
    print("-t testSequence         list of query-per-sec and duration tests as <qps1>:<t1>,... (e.g. 200:30,400:10)       [default: " + DEFAULT_TEST_SEQUENCE + "]")
    print("-i idleStrategy         Silkrpc: idle strategy for execution contexts                                          [default: " + DEFAULT_WAIT_MODE + "]")
    print("-n numContexts          Silkrpc: number of execution contexts (threading based on idle strategy)               [default: " + DEFAULT_SILKRPC_NUM_CONTEXTS + "]")
    print("-w testWaitInterval     time interval between successive test iterations in sec                                [default: " + str(DEFAULT_WAITING_TIME) + "]")
    print("-o workerThreads        Silkrpc: number of worker threads                                                      [default: " + DEFAULT_WORKERS + "]")
    sys.exit(-1)

def get_process(process_name: str):
    """ Return the running process having specified name or None if not exists """
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            return proc
    return None

class Config:
    # pylint: disable=too-many-instance-attributes
    """ This class manage configuration params """

    def __init__(self, argv):
        """ Processes the command line contained in argv """
        self.vegeta_pattern_tar_file = DEFAULT_VEGETA_PATTERN_TAR_FILE
        self.daemon_vegeta_on_core = DEFAULT_DAEMON_VEGETA_ON_CORE
        self.erigon_addr = DEFAULT_ERIGON_ADDRESS
        self.erigon_builddir = DEFAULT_ERIGON_BUILD_DIR
        self.silkrpc_build_dir = DEFAULT_SILKRPC_BUILD_DIR
        self.silkrpc_num_contexts = DEFAULT_SILKRPC_NUM_CONTEXTS
        self.repetitions = DEFAULT_REPETITIONS
        self.test_sequence = DEFAULT_TEST_SEQUENCE
        self.rpc_daemon_address = DEFAULT_RPCDAEMON_ADDRESS
        self.test_mode = DEFAULT_TEST_MODE
        self.test_type = DEFAULT_TEST_TYPE
        self.waiting_time = DEFAULT_WAITING_TIME
        self.user_perf_command = ""
        self.workers = DEFAULT_WORKERS
        self.start_server = "1"
        self.wait_mode = DEFAULT_WAIT_MODE
        self.versioned_test_report = False
        self.verbose = False
        self.check_server_alive = True
        self.tracing = False

        self.__parse_args(argv)

    def __parse_args(self, argv):
        try:
            local_config = 0
            opts, _ = getopt.getopt(argv[1:], "D:hm:d:p:c:a:g:s:r:t:n:y:zw:i:o:uvxZ")

            for option, optarg in opts:
                if option in ("-h", "--help"):
                    usage(argv)
                elif option == "-m":
                    self.test_mode = optarg
                elif option == "-D":
                    self.user_perf_command = optarg
                elif option == "-d":
                    if local_config == 1:
                        print("ERROR: incompatible option -d with -a -g -s -n")
                        usage(argv)
                    local_config = 2
                    self.rpc_daemon_address = optarg
                elif option == "-p":
                    self.vegeta_pattern_tar_file = optarg
                elif option == "-c":
                    self.daemon_vegeta_on_core = optarg
                elif option == "-a":
                    if local_config == 2:
                        print("ERROR: incompatible option -d with -a -g -s -n")
                        usage(argv)
                    local_config = 1
                    self.erigon_addr = optarg
                elif option == "-g":
                    if local_config == 2:
                        print("ERROR: incompatible option -d with -a -g -s -n")
                        usage(argv)
                    local_config = 1
                    self.erigon_builddir = optarg
                elif option == "-s":
                    if local_config == 2:
                        print("ERROR: incompatible option -d with -a -g -s -n")
                        usage(argv)
                    local_config = 1
                    self.silkrpc_build_dir = optarg
                elif option == "-o":
                    self.workers = optarg
                elif option == "-r":
                    self.repetitions = int(optarg)
                elif option == "-t":
                    self.test_sequence = optarg
                elif option == "-z":
                    self.start_server = "0"
                elif option == "-u":
                    self.versioned_test_report = True
                elif option == "-v":
                    self.verbose = True
                elif option == "-x":
                    self.verbose = True
                    self.tracing = True
                elif option == "-w":
                    self.waiting_time = int(optarg)
                elif option == "-y":
                    self.test_type = optarg
                elif option == "-i":
                    self.wait_mode = optarg
                elif option == "-Z":
                    self.check_server_alive = False
                elif option == "-n":
                    if local_config == 2:
                        print("ERROR: incompatible option -d with -a -g -s -n")
                        usage(argv)
                    local_config = 1
                    self.silkrpc_num_contexts = optarg
                else:
                    usage(argv)
        except getopt.GetoptError as err:
            # print help information and exit:
            print(err)
            usage(argv)
            sys.exit(-1)


class PerfTest:
    """ This class manage performance test """

    def __init__(self, test_report, config):
        """ The initialization routine stop any previos server """
        self.test_report = test_report
        self.config = config
        self.cleanup()
        if self.config.verbose:
            print("Stop both RPC daemons in case they are already running...", end='', flush=True)
        if self.config.tracing:
            print("")
        self.stop_silk_daemon()
        self.stop_rpc_daemon()
        if self.config.verbose:
            print("done", flush=True)
        if self.config.verbose:
            print("Start-and-stop both RPC daemons just to check that configuration is OK...", end='', flush=True)
        if self.config.tracing:
            print("")
        self.start_silk_daemon(0)
        self.stop_silk_daemon()
        self.start_rpc_daemon(0)
        self.stop_rpc_daemon()
        if self.config.verbose:
            print("done", flush=True)
        self.copy_and_extract_pattern_file()

    def cleanup(self):
        """ Cleanup temporary files """
        self.silk_daemon = 0
        self.rpc_daemon = 0
        cmd = "/bin/rm -f " +  " /tmp/" + VEGETA_TAR_FILE_NAME
        os.system(cmd)
        cmd = "/bin/rm -f -rf /tmp/" + VEGETA_PATTERN_DIRNAME
        os.system(cmd)
        cmd = "/bin/rm -f perf.data.old perf.data"
        os.system(cmd)

    def copy_and_extract_pattern_file(self):
        """ Copy the vegeta pattern file into /tmp and untar the file """
        cmd = "/bin/cp -f " + self.config.vegeta_pattern_tar_file + " /tmp/" + VEGETA_TAR_FILE_NAME
        if self.config.tracing:
            print(f"Copy Vegeta pattern: {cmd}")
        status = os.system(cmd)
        if int(status) != 0:
            print("Vegeta pattern copy failed. Test Aborted!")
            sys.exit(-1)

        cmd = "cd /tmp; tar xvf " + VEGETA_TAR_FILE_NAME + " > /dev/null"
        if self.config.tracing:
            print(f"Extracting Vegeta pattern: {cmd}")
        status = os.system(cmd)
        if int(status) != 0:
            print("Vegeta pattern untar failed. Test Aborted!")
            sys.exit(-1)

        # If address is provided substitute the address and port of daemon in the vegeta file
        if self.config.rpc_daemon_address != "localhost":
            cmd = "sed -i 's/localhost/" + self.config.rpc_daemon_address + "/g' " + VEGETA_PATTERN_SILKRPC_BASE + self.config.test_type + ".txt"
            os.system(cmd)
            cmd = "sed -i 's/localhost/" + self.config.rpc_daemon_address + "/g' " + VEGETA_PATTERN_RPCDAEMON_BASE + self.config.test_type + ".txt"
            os.system(cmd)

    def start_rpc_daemon(self, start_test):
        """ Start Erigon RPC daemon server """
        if self.config.rpc_daemon_address != "localhost":
            return
        if self.config.start_server == "0":
            if start_test:
                print("Erigon RpcDaemon NOT started")
            return
        if self.config.test_mode == "1":
            return
        self.rpc_daemon = 1
        on_core = self.config.daemon_vegeta_on_core.split(':')
        if on_core[0] == "-":
            cmd = self.config.erigon_builddir + "bin/rpcdaemon --private.api.addr="+self.config.erigon_addr+" --http.api=eth,debug,net,web3 2>/dev/null &"
        else:
            cmd = "taskset -c " + on_core[0] + " " + \
                   self.config.erigon_builddir + "bin/rpcdaemon --private.api.addr="+self.config.erigon_addr+" --http.api=eth,debug,net,web3 2>/dev/null &"
        if self.config.tracing:
            print(f"Erigon RpcDaemon starting: {cmd}")
        status = os.system(cmd)
        if int(status) != 0:
            print("Start Erigon RpcDaemon failed: Test Aborted!")
            sys.exit(-1)
        time.sleep(2)
        rpcdaemon_process = get_process('rpcdaemon')
        if not rpcdaemon_process:
            print("Start Erigon RpcDaemon failed: Test Aborted!")
            sys.exit(-1)

    def stop_rpc_daemon(self):
        """ Stop Erigon RPC daemon server """
        if self.config.rpc_daemon_address != "localhost":
            return
        if self.config.start_server == "0":
            return
        if self.config.test_mode == "1":
            return
        self.rpc_daemon = 0
        os.system("kill -9 $(ps aux | grep 'rpcdaemon' | grep -v 'grep' | awk '{print $2}') 2> /dev/null")
        rpcdaemon_process = get_process('rpcdaemon')
        if rpcdaemon_process:
            rpcdaemon_process.kill()
        if self.config.tracing:
            print("Erigon RpcDaemon stopped")
        time.sleep(5)

    def start_silk_daemon(self, start_test):
        """ Starts Silkrpc daemon """
        if self.config.rpc_daemon_address != "localhost":
            return
        if self.config.start_server == "0":
            if start_test:
                print("Silkrpc NOT started")
            return
        if self.config.test_mode == "2":
            return
        self.rpc_daemon = 1
        on_core = self.config.daemon_vegeta_on_core.split(':')
        if self.config.user_perf_command != "" and start_test == 1:
            perf_cmd = self.config.user_perf_command
        else:
            perf_cmd = ""
        wait_mode_str = " --wait_mode " + self.config.wait_mode

        base_params = self.config.silkrpc_build_dir + "cmd/silkrpcdaemon --target " + self.config.erigon_addr + " --http_port localhost:51515 --log_verbosity c --num_workers " \
            + str(self.config.workers)

        if self.config.silkrpc_num_contexts != "":
            base_params += " --num_contexts " + str(self.config.silkrpc_num_contexts)
        if on_core[0] == "-":
            cmd = perf_cmd  + base_params + wait_mode_str + " 2>/dev/null &"
        else:
            cmd = perf_cmd + "taskset -c " + on_core[0] + " "  + base_params + wait_mode_str + " 2>/dev/null &"
        if self.config.tracing:
            print(f"Silkrpc starting: {cmd}")
        status = os.system(cmd)
        if int(status) != 0:
            print("Start Silkrpc failed: Test Aborted!")
            sys.exit(-1)
        time.sleep(2)
        silkrpc_process = get_process('silkrpcdaemon')
        if not silkrpc_process:
            print("Start Silkrpc failed: Test Aborted!")
            sys.exit(-1)

    def stop_silk_daemon(self):
        """ Stops Silkrpc daemon """
        if self.config.rpc_daemon_address != "localhost":
            return
        if self.config.start_server == "0":
            return
        if self.config.test_mode == "2":
            return
        self.silk_daemon = 0
        silkrpc_process = get_process('silkrpcdaemon')
        if silkrpc_process:
            silkrpc_process.kill()
        if self.config.tracing:
            print("Silkrpc stopped")
        time.sleep(3)

    def execute(self, test_number, name, qps_value, duration):
        """ Execute the tests using specified queries-per-second (QPS) and duration """
        if name == "silkrpc":
            pattern = VEGETA_PATTERN_SILKRPC_BASE + self.config.test_type + ".txt"
        else:
            pattern = VEGETA_PATTERN_RPCDAEMON_BASE + self.config.test_type + ".txt"
        on_core = self.config.daemon_vegeta_on_core.split(':')
        if on_core[1] == "-":
            cmd = "cat " + pattern + " | " \
                  "vegeta attack -keepalive -rate=" + qps_value + " -format=json -duration=" + duration + "s -timeout=300s | " \
                  "vegeta report -type=text > " + VEGETA_REPORT + " &"
        else:
            cmd = "taskset -c " + on_core[1] + " cat " + pattern + " | " \
                  "taskset -c " + on_core[1] + " vegeta attack -keepalive -rate=" + qps_value + " -format=json -duration=" + duration + "s -timeout=300s | " \
                  "taskset -c " + on_core[1] + " vegeta report -type=text > " + VEGETA_REPORT + " &"
        print(f"{test_number} {name}: executes test qps: {qps_value} time: {duration} -> ", end="")
        sys.stdout.flush()
        status = os.system(cmd)
        if int(status) != 0:
            print("vegeta test fails: Test Aborted!")
            return 0

        while 1:
            time.sleep(3)
            if self.config.check_server_alive:
                if name == "silkrpc":
                    pid = os.popen("ps aux | grep 'silkrpc' | grep -v 'grep' | awk '{print $2}'").read()
                else:
                    pid = os.popen("ps aux | grep 'rpcdaemon' | grep -v 'grep' | awk '{print $2}'").read()
                if pid == "" :
                    # the server is dead; kill vegeta and returns fails
                    os.system("kill -2 $(ps aux | grep 'vegeta' | grep -v 'grep' | grep -v 'python' | awk '{print $2}') 2> /dev/null")
                    return 0

            pid = os.popen("ps aux | grep 'vegeta report' | grep -v 'grep' | awk '{print $2}'").read()
            if pid == "":
                # Vegeta has completed its works, generate report and return OK
                self.get_result(test_number, name, qps_value, duration)
                return 1

    def execute_sequence(self, sequence, tag):
        """ Execute the sequence of tests """
        test_number = 1
        for test in sequence:
            for test_rep in range(0, self.config.repetitions):
                qps = test.split(':')[0]
                duration = test.split(':')[1]
                test_name = "[{:d}.{:2d}] "
                test_name_formatted = test_name.format(test_number, test_rep+1)
                result = self.execute(test_name_formatted, tag, qps, duration)
                if result == 0:
                    print("Server dead test Aborted!")
                    return 0
                time.sleep(self.config.waiting_time)
            test_number = test_number + 1
            print("")
        return 1

    def get_result(self, test_number, daemon_name, qps_value, duration):
        """ Processes the report file generated by vegeta and reads latency data """
        test_report_filename = VEGETA_REPORT
        file = open(test_report_filename, encoding='utf8')
        try:
            file_raws = file.readlines()
            newline = file_raws[2].replace('\n', ' ')
            latency_values = newline.split(',')
            min_latency = latency_values[6].split(']')[1]
            max_latency = latency_values[12]
            newline = file_raws[5].replace('\n', ' ')
            ratio = newline.split(' ')[34]
            if len(file_raws) > 8:
                error = file_raws[8]
                print(" [ Ratio="+ratio+", MaxLatency="+max_latency+ " Error: " + error +"]")
            else:
                error = ""
                print(" [ Ratio="+ratio+", MaxLatency="+max_latency+"]")
            threads = os.popen("ps -efL | grep erigon | grep bin | wc -l").read().replace('\n', ' ')
        finally:
            file.close()

        self.test_report.write_test_report(daemon_name, test_number, threads, qps_value, duration, min_latency, latency_values[7], latency_values[8], \
                                           latency_values[9], latency_values[10], latency_values[11], max_latency, ratio, error)
        os.system("/bin/rm " + test_report_filename)


class Hardware:
    """ Extract hardware information from the underlying platform. """

    @classmethod
    def vendor(cls):
        """ Return the system vendor """
        command = "cat /sys/devices/virtual/dmi/id/sys_vendor"
        return os.popen(command).readline().replace('\n', '')

    @classmethod
    def normalized_vendor(cls):
        """ Return the system vendor as lowercase first-token splitted by whitespace """
        return cls.vendor().split(' ')[0].lower()

    @classmethod
    def product(cls):
        """ Return the system product name """
        command = "cat /sys/devices/virtual/dmi/id/product_name"
        return os.popen(command).readline().replace('\n', '')

    @classmethod
    def normalized_product(cls):
        """ Return the system product name as lowercase w/o whitespaces """
        return cls.product().replace(' ', '').lower()

class TestReport:
    """ The Comma-Separated Values (CSV) test report """

    def __init__(self, config):
        """ Create a new TestReport """
        self.csv_file = ''
        self.writer = ''
        self.config = config

    def open(self):
        """ Writes on CSV file the header """
        # Build report folder w/ name recalling hw platform and create it if not exists
        csv_folder = Hardware.normalized_vendor() + '_' + Hardware.normalized_product()
        if self.config.versioned_test_report:
            csv_folder_path = self.config.silkrpc_build_dir + '../tests/perf/reports/goerli/' + csv_folder
        else:
            csv_folder_path = '/tmp/goerli/' + csv_folder
        pathlib.Path(csv_folder_path).mkdir(parents=True, exist_ok=True)

        # Generate unique CSV file name w/ date-time and open it
        csv_filename = datetime.today().strftime('%Y-%m-%d-%H:%M:%S') + "_perf.csv"
        csv_filepath = csv_folder_path + '/' + csv_filename
        self.csv_file = open(csv_filepath, 'w', newline='', encoding='utf8')
        self.writer = csv.writer(self.csv_file)

        print("Perf report file: " + csv_filepath + "\n")

        command = "sum "+ self.config.vegeta_pattern_tar_file
        checksum = os.popen(command).read().split('\n')

        command = "gcc --version"
        gcc_vers = os.popen(command).read().split(',')

        command = "go version"
        go_vers = os.popen(command).read().replace('\n', '')

        command = "uname -r"
        kern_vers = os.popen(command).read().replace('\n', "").replace('\'', '')

        command = "cat /proc/cpuinfo | grep 'model name' | uniq"
        model = os.popen(command).readline().replace('\n', ' ').split(':')
        command = "cat /proc/cpuinfo | grep 'bogomips' | uniq"
        tmp = os.popen(command).readline().replace('\n', '').split(':')[1]
        bogomips = tmp.replace(' ', '')

        erigon_branch = ""
        erigon_commit = ""
        silkrpc_branch = ""
        silkrpc_commit = ""
        if self.config.test_mode in ("1", "3"):
            command = "cd " + self.config.silkrpc_build_dir + " && git branch --show-current"
            silkrpc_branch = os.popen(command).read().replace('\n', '')

            command = "cd " + self.config.silkrpc_build_dir + " && git rev-parse HEAD"
            silkrpc_commit = os.popen(command).read().replace('\n', '')

        if self.config.test_mode in ("2", "3"):
            command = "cd " + self.config.erigon_builddir + " && git branch --show-current"
            erigon_branch = os.popen(command).read().replace('\n', '')

            command = "cd " + self.config.erigon_builddir + " && git rev-parse HEAD"
            erigon_commit = os.popen(command).read().replace('\n', '')

        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Vendor", Hardware.vendor()])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Product", Hardware.product()])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "CPU", model[1]])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Bogomips", bogomips])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Kernel", kern_vers])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "DaemonVegetaRunOnCore", self.config.daemon_vegeta_on_core])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Erigon address", self.config.erigon_addr])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "VegetaFile", self.config.vegeta_pattern_tar_file])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "VegetaChecksum", checksum[0]])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "GCC version", gcc_vers[0]])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Go version", go_vers])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Silkrpc version", silkrpc_branch + " " + silkrpc_commit])
        self.writer.writerow(["", "", "", "", "", "", "", "", "", "", "", "", "Erigon version", erigon_branch + " " + erigon_commit])
        self.writer.writerow([])
        self.writer.writerow([])
        self.writer.writerow(["Daemon", "TestNo", "TG-Threads", "Qps", "Time", "Min", "Mean", "50", "90", "95", "99", "Max", "Ratio", "Error"])
        self.csv_file.flush()

    def write_test_report(self, daemon, test_number, threads, qps_value, duration, min_latency, mean, fifty, ninty, nintyfive, nintynine, max_latency, ratio, error):
        """ Writes on CSV the latency data for one completed test """
        self.writer.writerow([daemon, str(test_number), threads, qps_value, duration, min_latency, mean, fifty, ninty, nintyfive, nintynine, max_latency, ratio, error])
        self.csv_file.flush()

    def close(self):
        """ Close the report """
        self.csv_file.flush()
        self.csv_file.close()


#
# main
#
def main(argv):
    """ Execute performance tests on selected user configuration """
    print("Performance Test started")
    config = Config(argv)
    test_report = TestReport(config)
    perf_test = PerfTest(test_report, config)

    print(f"Test repetitions: {config.repetitions} on sequence: {config.test_sequence} for pattern: {config.vegeta_pattern_tar_file}")
    test_report.open()

    current_sequence = str(config.test_sequence).split(',')

    if config.test_mode in ("1", "3"):
        perf_test.start_silk_daemon(1)
        result = perf_test.execute_sequence(current_sequence, 'silkrpc')
        if result == 0:
            print("Server dead test Aborted!")
            test_report.close()
            sys.exit(-1)
        perf_test.stop_silk_daemon()
        if config.test_mode == "3":
            print("--------------------------------------------------------------------------------------------\n")

    if config.test_mode in ("2", "3"):
        perf_test.start_rpc_daemon(1)
        result = perf_test.execute_sequence(current_sequence, 'rpcdaemon')
        if result == 0:
            print("Server dead test Aborted!")
            test_report.close()
            sys.exit(-1)
        perf_test.stop_rpc_daemon()

    test_report.close()
    print("Performance Test completed successfully.")


#
# module as main
#
if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
