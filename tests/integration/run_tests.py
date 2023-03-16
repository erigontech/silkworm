#!/usr/bin/python3
""" Run the JSON RPC API curl commands as integration tests """

from datetime import datetime
import getopt
import gzip
import json
#import jsondiff
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import pytz
import jwt

SILK="silk"
RPCDAEMON="rpcdaemon"
INFURA="infura"

tests_with_big_json = [
   "debug_traceBlockByHash/test_02.tar",
   "debug_traceBlockByHash/test_03.tar",
   "debug_traceBlockByHash/test_04.tar",
   "debug_traceBlockByNumber/test_02.tar",
   "trace_replayBlockTransactions/test_01.tar",
   "trace_replayBlockTransactions/test_02.tar",
   "trace_replayTransaction/test_16.tar",
   "trace_replayTransaction/test_23.tar"
]

api_not_compared = [
   "trace_rawTransaction",
   "parity_getBlockReceipts",
   "txpool_content"
]

tests_not_compared = [
   "debug_traceBlockByHash/test_02.tar",
   "debug_traceBlockByHash/test_03.tar",
   "debug_traceBlockByHash/test_04.tar",
   "debug_traceBlockByNumber/test_02.tar",
   "debug_traceCall/test_10.json",
   "debug_traceCall/test_14.json",
   "debug_traceCall/test_17.json"
]

def get_target(target_type: str, method: str, infura_url: str, host: str):
    """ determine target
    """
    if "engine_" in method and target_type == SILK:
        return host + ":51516"

    if "engine_" in method and target_type == RPCDAEMON:
        return host + ":8551"

    if target_type == SILK:
        return host + ":51515"

    if target_type == INFURA:
        return infura_url

    return host + ":8545"

def get_json_filename_ext(target_type: str):
    """ determine json file name
    """
    if target_type == SILK:
        return "-silk.json"
    if target_type == INFURA:
        return "-infura.json"
    return "-rpcdaemon.json"

#
#
#
def get_jwt_secret(name):
    """ parse secret file
    """
    try:
        with open(name, encoding='utf8') as file:
            contents = file.readline()
            return contents[2:]
    except FileNotFoundError:
        return ""



def is_skipped(api_name, exclude_api_list, exclude_test_list, api_file: str, req_test, verify_with_daemon, global_test_number):
    """ determine if test must be skipped
    """
    if req_test == -1 and verify_with_daemon == 1:
        for curr_test_name in api_not_compared:
            if curr_test_name == api_name:
                return 1
    if req_test == -1 and verify_with_daemon == 1:
        for curr_test in tests_not_compared:
            if curr_test == api_file:
                return 1
    if exclude_api_list != "": # scans exclude api list (-x)
        tokenize_exclude_api_list = exclude_api_list.split(",")
        for exclude_api in tokenize_exclude_api_list:
            if exclude_api in api_name:
                return 1
    if exclude_test_list != "": # scans exclude test list (-X)
        tokenize_exclude_test_list = exclude_test_list.split(",")
        for exclude_test in tokenize_exclude_test_list:
            if exclude_test == str(global_test_number):
                return 1
    return 0

def is_big_json(test_name: str):
    """ determine if json is in the big list
    """
    for curr_test_name in tests_with_big_json:
        if curr_test_name == test_name:
            return 1
    return 0

def run_shell_command(command: str, command1: str, expected_response: str, verbose: bool, exit_on_fail: bool, output_dir: str, silk_file: str,
                      exp_rsp_file: str, diff_file: str, dump_output, json_file: str, test_number):
    """ Run the specified command as shell. If exact result or error don't care, they are null but present in expected_response. """

    command_and_args = shlex.split(command)
    process = subprocess.run(command_and_args, stdout=subprocess.PIPE, universal_newlines=True, check=True)
    if process.returncode != 0:
        sys.exit(process.returncode)
    process.stdout = process.stdout.strip('\n')
    #print (process.stdout)
    response = json.loads(process.stdout)
    if command1 != "":
        command_and_args = shlex.split(command1)
        process = subprocess.run(command_and_args, stdout=subprocess.PIPE, universal_newlines=True, check=True)
        if process.returncode != 0:
            sys.exit(process.returncode)
        process.stdout = process.stdout.strip('\n')
        try:
            expected_response = json.loads(process.stdout)
        except json.decoder.JSONDecodeError:
            if verbose:
                print("Failed (bad json format on expected rsp)")
                print(process.stdout)
                return 1
            file = json_file.ljust(60)
            print(f"{test_number:03d}. {file} Failed (bad json format on expected rsp)")
            if exit_on_fail:
                print("TEST ABORTED!")
                sys.exit(1)
            return 1

    if response != expected_response:
        if "result" in response and "result" in expected_response and expected_response["result"] is None:
            # response and expected_response are different but don't care
            if verbose:
                print("OK")
            return 0
        if "error" in response and "error" in expected_response and expected_response["error"] is None:
            # response and expected_response are different but don't care
            if verbose:
                print("OK")
            return 0
        if (silk_file != "" and os.path.exists(output_dir) == 0):
            os.mkdir (output_dir)
        if silk_file != "":
            with open(silk_file, 'w', encoding='utf8') as json_file_ptr:
                json_file_ptr.write(json.dumps(response,  indent=5))
        if exp_rsp_file != "":
            with open(exp_rsp_file, 'w', encoding='utf8') as json_file_ptr:
                json_file_ptr.write(json.dumps(expected_response,  indent=5))
        #response_diff = jsondiff.diff(expected_response, response, marshal=True)
        if is_big_json(json_file):
            cmd = "json-patch-jsondiff --indent 4 " + exp_rsp_file  + " " + silk_file + " > " + diff_file
        else:
            cmd = "json-diff -s " + exp_rsp_file  + " " + silk_file + " > " + diff_file
        os.system(cmd)
        diff_file_size = os.stat(diff_file).st_size
        if diff_file_size != 0:
            if verbose:
                print("Failed")
            else:
                file = json_file.ljust(60)
                print(f"{test_number:03d}. {file} Failed")
            if exit_on_fail:
                print("TEST ABORTED!")
                sys.exit(1)
            return 1
        if verbose:
            print("OK")
        os.remove(silk_file)
        os.remove(exp_rsp_file)
        os.remove(diff_file)
        os.rmdir(output_dir)
    else:
        if verbose:
            print("OK")
        if dump_output:
            if (silk_file != "" and os.path.exists(output_dir) == 0):
                os.mkdir (output_dir)
            if silk_file != "":
                with open(silk_file, 'w', encoding='utf8') as json_file_ptr:
                    json_file_ptr.write(json.dumps(response, indent = 6))
            if exp_rsp_file != "":
                with open(exp_rsp_file, 'w', encoding='utf8') as json_file_ptr:
                    json_file_ptr.write(json.dumps(expected_response,  indent=5))
    return 0

def run_tests(test_dir: str, output_dir: str, json_file: str, verbose: bool, daemon_under_test: str, exit_on_fail: bool, verify_with_daemon: bool, daemon_as_reference: str,
              dump_output: bool, test_number, infura_url: str, daemon_on_host: str, jwt_secret: str):
    """ Run integration tests. """
    json_filename = test_dir + json_file
    ext = os.path.splitext(json_file)[1]

    if ext in (".zip", ".tar"):
        with tarfile.open(json_filename,encoding='utf-8') as tar:
            files = tar.getmembers()
            if len(files) != 1:
                print ("bad archive file " + json_filename)
                sys.exit(1)
            file = tar.extractfile(files[0])
            buff = file.read()
            tar.close()
            jsonrpc_commands = json.loads(buff)
    elif ext in (".gzip"):
        with gzip.open(json_filename,'rb') as zipped_file:
            buff=zipped_file.read()
            jsonrpc_commands = json.loads(buff)
    else:
        with open(json_filename, encoding='utf8') as json_file_ptr:
            jsonrpc_commands = json.load(json_file_ptr)
    for json_rpc in jsonrpc_commands:
        request = json_rpc["request"]
        try:
            if isinstance(request, dict) == 1:
                method = request["method"]
            else:
                method = request[0]["method"]
        except KeyError:
            method = ""
        request_dumps = json.dumps(request)
        target = get_target(daemon_under_test, method, infura_url, daemon_on_host)
        if jwt_secret == "":
            jwt_auth = ""
        else:
            byte_array_secret = bytes.fromhex(jwt_secret)
            encoded = jwt.encode({"iat": datetime.now(pytz.utc)}, byte_array_secret, algorithm="HS256")
            jwt_auth = "-H \"Authorization: Bearer " + str(encoded) + "\" "
        if verify_with_daemon == 0:
            cmd = '''curl --silent -X POST -H "Content-Type: application/json" ''' + jwt_auth + ''' --data \'''' + request_dumps + '''\' ''' + target
            cmd1 = ""
            output_api_filename = output_dir + json_file[:-4]
            output_dir_name = output_api_filename[:output_api_filename.rfind("/")]
            response = json_rpc["response"]
            silk_file = output_api_filename + "-response.json"
            exp_rsp_file = output_api_filename + "-expResponse.json"
            diff_file = output_api_filename + "-diff.json"
        else:
            target = get_target(SILK, method, infura_url, daemon_on_host)
            target1 = get_target(daemon_as_reference, method, infura_url, daemon_on_host)
            cmd = '''curl --silent -X POST -H "Content-Type: application/json" ''' + jwt_auth + ''' --data \'''' + request_dumps + '''\' ''' + target
            cmd1 = '''curl --silent -X POST -H "Content-Type: application/json" ''' + jwt_auth + ''' --data \'''' + request_dumps + '''\' ''' + target1
            output_api_filename = output_dir + json_file[:-4]
            output_dir_name = output_api_filename[:output_api_filename.rfind("/")]
            response = ""
            silk_file = output_api_filename + get_json_filename_ext(SILK)
            exp_rsp_file = output_api_filename + get_json_filename_ext(daemon_as_reference)
            diff_file = output_api_filename + "-diff.json"

        return run_shell_command(
                cmd,
                cmd1,
                response,
                verbose,
                exit_on_fail,
                output_dir_name,
                silk_file,
                exp_rsp_file,
                diff_file,
                dump_output,
                json_file,
                test_number)

#
# usage
#
def usage(argv):
    """ Print script usage
    """
    print("Usage: " + argv[0] + ":")
    print("")
    print("Launch an automated test sequence on Silkrpc or RPCDaemon")
    print("")
    print("-h print this help")
    print("-c runs all tests even if one test fails [ default exit at first test fail ]")
    print("-r connect to rpcdaemon [ default connect to silk ] ")
    print("-l <number of loops>")
    print("-a <test api >: run all tests of the specified API")
    print("-s <start_test_number>: run tests starting from input")
    print("-t <test_number>: run single test")
    print("-d provides same request also to the reference daemon (default RPCDAEMON)")
    print("-i provides request also to the reference daemon (INFURA)")
    print("-b blockchain (default goerly)")
    print("-v verbose")
    print("-o dump response")
    print("-k authentication token file")
    print("-x exclude api list (i.e txpool_content,txpool_status,engine_")
    print("-X exclude test list (i.e 18,22")
    print("-H host where the daemon is located(i.e 10.10.2.3)")

#
# main
#
def main(argv):
    """ parse command line and execute tests
    """
    exit_on_fail = 1
    daemon_under_test = SILK
    daemon_as_reference = RPCDAEMON
    loop_number = 1
    verbose = 0
    req_test = -1
    dump_output = 0
    infura_url = ""
    daemon_on_host = "localhost"
    requested_api = ""
    verify_with_daemon = 0
    json_dir = "./goerly/"
    results_dir = "results"
    output_dir = json_dir + results_dir + "/"
    exclude_api_list = ""
    exclude_test_list = ""
    start_test = ""
    jwt_secret = ""

    try:
        opts, _ = getopt.getopt(argv[1:], "hrcvt:l:a:di:b:ox:X:H:k:s:")
        for option, optarg in opts:
            if option in ("-h", "--help"):
                usage(argv)
                sys.exit(-1)
            elif option == "-c":
                exit_on_fail = 0
            elif option == "-r":
                daemon_under_test = RPCDAEMON
            elif option == "-i":
                daemon_as_reference = INFURA
                infura_url = optarg
            elif option == "-H":
                daemon_on_host = optarg
            elif option == "-v":
                verbose = 1
            elif option == "-t":
                req_test = int(optarg)
            elif option == "-s":
                start_test = int(optarg)
            elif option == "-a":
                requested_api = optarg
            elif option == "-l":
                loop_number = int(optarg)
            elif option == "-d":
                verify_with_daemon = 1
            elif option == "-o":
                dump_output = 1
            elif option == "-b":
                json_dir = "./" + optarg + "/"
            elif option == "-x":
                exclude_api_list = optarg
            elif option == "-X":
                exclude_test_list = optarg
            elif option == "-k":
                jwt_secret = get_jwt_secret(optarg)
                if jwt_secret == "":
                    print ("secret file not found")
                    sys.exit(-1)
            else:
                usage(argv)
                sys.exit(-1)

    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)
        usage(argv)
        sys.exit(-1)

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    start_time = time.time()
    os.mkdir (output_dir)
    match = 0
    failed_tests = 0
    success_tests = 0
    tests_not_executed = 0
    for test_rep in range(0, loop_number):
        if verbose:
            print("Test iteration: ", test_rep + 1)
        dirs = sorted(os.listdir(json_dir))
        executed_tests = 0
        global_test_number = 1
        for api_file in dirs:
            # jump result_dir
            if api_file == results_dir:
                continue
            test_dir = json_dir + api_file
            test_lists = sorted(os.listdir(test_dir))
            test_number = 1
            for test_name in test_lists:
                if requested_api in api_file or requested_api == "": # -a
                    test_file = api_file + "/" + test_name
                    if  is_skipped(api_file, exclude_api_list, exclude_test_list, test_file, req_test, verify_with_daemon, global_test_number) == 1:
                        if start_test == "" or global_test_number >= int(start_test):
                            file = test_file.ljust(60)
                            print(f"{global_test_number:03d}. {file} Skipped")
                            tests_not_executed = tests_not_executed + 1
                    else:
                        # runs all tests req_test refers global test number or
                        # runs only tests on specific api req_test refers all test on specific api
                        if (requested_api == "" and req_test in (-1, global_test_number)) or (requested_api != "" and req_test in (-1, test_number)):
                            if (start_test == "") or (start_test != "" and global_test_number >= int(start_test)):
                                file = test_file.ljust(60)
                                if verbose:
                                    print(f"{global_test_number:03d}. {file} ", end = '', flush=True)
                                else:
                                    print(f"{global_test_number:03d}. {file}\r", end = '', flush=True)
                                ret=run_tests(json_dir, output_dir, test_file, verbose, daemon_under_test, exit_on_fail, verify_with_daemon, daemon_as_reference,
                                          dump_output, global_test_number, infura_url, daemon_on_host, jwt_secret)
                                if ret == 0:
                                    success_tests = success_tests + 1
                                else:
                                    failed_tests = failed_tests + 1
                                executed_tests = executed_tests + 1
                                if req_test != -1 or requested_api != "":
                                    match = 1

                global_test_number = global_test_number + 1
                test_number = test_number + 1

    if (req_test != -1 or requested_api != "") and match == 0:
        print("ERROR: api or testNumber not found")
    else:
        end_time = time.time()
        elapsed = end_time - start_time
        print("                                                                                    \r")
        print(f"Test time-elapsed (secs):     {int(elapsed)}")
        print(f"Number of executed tests:     {executed_tests}/{global_test_number-1}")
        print(f"Number of NOT executed tests: {tests_not_executed}")
        print(f"Number of success tests:      {success_tests}")
        print(f"Number of failed tests:       {failed_tests}")
#
# module as main
#
if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
