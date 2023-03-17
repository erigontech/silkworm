#!/usr/bin/python3
""" Creates a Raw transaction """

import sys
import getopt
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('https://goerli.infura.io/v3/06ffc77ca4534edb84483033573d18cb'))


def usage(argv):
    """ print usage string
    """
    print("Usage: " + argv[0] +
          " -k <key-file> -p <password> -f <from account address> -t <to account address>")
#
# main
#
def main(argv):
    """ parse command line and generated signed transaction
    """
    try:
        opts, _ = getopt.getopt(argv[1:], "k:p:f:t:")
        for option, optarg in opts:
            if option in ("-h", "--help"):
                usage(argv)
                sys.exit(-1)
            elif option == "-k":
                key_file = optarg
            elif option == "-p":
                password = optarg
            elif option == "-f":
                from_account = optarg
            elif option == "-t":
                to_account = optarg
            elif option == "-h":
                usage(argv)
            else:
                usage(argv)
                sys.exit(-1)

    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)
        usage(argv)
        sys.exit(-1)

    with open(key_file, encoding="utf8") as key_file:
        encrypted_key = key_file.read()
        private_key = w3.eth.account.decrypt(encrypted_key, password)

    signed_txn = w3.eth.account.signTransaction(dict(
        nonce=w3.eth.getTransactionCount(from_account),
        gasPrice = w3.eth.gasPrice,
        gas = 100000,
        chainId=5,
        to=to_account,
        value=w3.toWei(0,'ether')),
        private_key)

    print (signed_txn)

#
# module as main
#
if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)
