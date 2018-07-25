#!/usr/bin/python
# -*- coding: utf-8 -*-
# Test

"""
Example of running a NEO node, receiving smart contract notifications and
integrating a simple REST API.

Smart contract events include Runtime.Notify, Runtime.Log, Storage.*,
Execution.Success and several more. See the documentation here:
http://neo-python.readthedocs.io/en/latest/smartcontracts.html

This example requires the environment variable NEO_REST_API_TOKEN, and can
optionally use NEO_REST_LOGFILE and NEO_REST_API_PORT.

Example usage (with "123" as valid API token):

    NEO_REST_API_TOKEN="123" python examples/smart-contract-rest-api.py

Example API calls:

    $ curl localhost:8080
    $ curl -H "Authorization: Bearer 123" localhost:8080/echo/hello123
    $ curl -X POST -H "Authorization: Bearer 123" -d '{ "hello": "world" }' localhost:8080/echo-post

The REST API is using the Python package 'klein', which makes it possible to
create HTTP routes and handlers with Twisted in a similar style to Flask:
https://github.com/twisted/klein
"""

import os
import threading
import datetime
import json
import time
from time import sleep
import re
import requests

from logzero import logger
from twisted.internet import reactor, task, endpoints
from twisted.web.server import Request, Site
from klein import Klein, resource

from neo.Network.NodeLeader import NodeLeader
from neo.Core.Blockchain import Blockchain
from neo.Implementations.Blockchains.LevelDB.LevelDBBlockchain import LevelDBBlockchain
from neo.Settings import settings

from neo.Network.api.decorators import json_response, \
    gen_authenticated_decorator, catch_exceptions
from neo.contrib.smartcontract import SmartContract
from neo.SmartContract.ContractParameter import ContractParameter, \
    ContractParameterType

from neo.Wallets.utils import to_aes_key
from prompt_toolkit.styles import Style
from neo.UserPreferences import preferences
from neo.Implementations.Wallets.peewee.UserWallet import UserWallet
from twisted.internet import reactor, task
from neo.Prompt.Commands.LoadSmartContract import LoadContract, GatherContractDetails, ImportContractAddr, \
    ImportMultiSigContractAddr
from neo.Prompt.Commands.Invoke import InvokeContract, TestInvokeContract, test_invoke
from neo.Prompt.Commands.BuildNRun import BuildAndRun, LoadAndRun

# Set the hash of your contract here:

SMART_CONTRACT_HASH = '6537b4bd100e514119e3a7ab49d520d20ef2c2a4'

# Default REST API port is 8080, and can be overwritten with an env var:

API_PORT = os.getenv('NEO_REST_API_PORT', 8080)

# If you want to enable logging to a file, set the filename here:

LOGFILE = os.getenv('NEO_REST_LOGFILE', None)

# Internal: if LOGFILE is set, file logging will be setup with max
# 10 MB per file and 3 rotations:

if LOGFILE:
    settings.set_logfile(LOGFILE, max_bytes=1e7, backup_count=3)

# Internal: get the API token from an environment variable

API_AUTH_TOKEN = os.getenv('NEO_REST_API_TOKEN', None)
if not API_AUTH_TOKEN:
    raise Exception('No NEO_REST_API_TOKEN environment variable found!')

# Internal: setup the smart contract instance

smart_contract = SmartContract(SMART_CONTRACT_HASH)

# Internal: setup the klein instance

app = Klein()

# Internal: generate the @authenticated decorator with valid tokens

authenticated = gen_authenticated_decorator(API_AUTH_TOKEN)


#
# Smart contract event handler for Runtime.Notify events
#

#Define walletinfo as global scope
walletinfo = None

@smart_contract.on_notify
def sc_notify(event):
    logger.info('SmartContract Runtime.Notify event: %s', event)

    # Make sure that the event payload list has at least one element.

    if not isinstance(event.event_payload, ContractParameter) \
        or event.event_payload.Type != ContractParameterType.Array \
        or not len(event.event_payload.Value):
        return

    # The event payload list has at least one element. As developer of the smart contract
    # you should know what data-type is in the bytes, and how to decode it. In this example,
    # it's just a string, so we decode it with utf-8:

    logger.info('- payload part 1: %s',
                event.event_payload.Value[0].Value.decode('utf-8'))


#
# Custom code that runs in the background
#

class PromptInterface:

    token_style = None
    start_height = None
    start_dt = None
    Wallet = None

    def __init__(self):

        # self.input_parser = InputParser()

        self.start_height = Blockchain.Default().Height
        self.start_dt = datetime.datetime.utcnow()
        logger.info('TESTTT Block %s / %s', str(self.start_height),
                    str(self.start_dt))

        self.token_style = Style.from_dict({
            'command': preferences.token_style['Command'],
            'neo': preferences.token_style['Neo'],
            'default': preferences.token_style['Default'],
            'number': preferences.token_style['Number'],
            })


def custom_background_code():
    """ Custom code run in a background thread. Prints the current block height.

    This function is run in a daemonized thread, which means it can be instantly killed at any
    moment, whenever the main thread quits. If you need more safety, don't use a  daemonized
    thread and handle exiting this thread in another way (eg. with signals and events).
    """

    while True:
        logger.info('Block %s / %s', str(Blockchain.Default().Height),
                    str(Blockchain.Default().HeaderHeight))
        sleep(15)


#
# REST API Routes
#

@app.route('/')
def home(request):
    return 'Hello world'


@app.route('/echo/<msg>')
@catch_exceptions
@authenticated
@json_response
def echo_msg(request, msg):

    # promptInterface = PromptInterface();

    height = Blockchain.Default().Height
    headers = Blockchain.Default().HeaderHeight
    msg = headers - height
    return {'echo': msg}


@app.route('/echo-post', methods=['POST'])
@catch_exceptions
@authenticated
@json_response
def echo_post(request):

    # Parse POST JSON body

    body = json.loads(request.content.read().decode('utf-8'))
    print ('2 ----2 -> Incomming Body %s' % body)
    sc_location = body['smart_contract_location']
    r = requests.get(sc_location, allow_redirects=True)
    localtime = str(time.time())  # this removes the decimals
    temp_filename = localtime + sc_location
    filename = re.sub('[^ a-zA-Z0-9]', '', temp_filename)
    path = '/home/ubuntu/' + filename
    scname = path + '.py'
    avmname = '/'+path+'.avm'
    print ('3 ----3 -> Incomming FilePath %s' % scname)
    returnvalue = 'Issue in creating wallet.Please try manual approach'

    # Save SC.py file

    try:
        open(scname, 'wb').write(r.content)
    except Exception as e:
        print ('Exception creating file: %s' % e)
        return 'Issue Downloading and Saving your smart contract.Please try manual approach'

    # Deploy samrt contract  ....

    try:
        print ('4 ----4 -> Starting core process')
        Blockchain.Default().Pause()
        print ('4.1 ----4 ->scname %s' %scname)
        print ('4.2 ----4 -> Starting core process %s' %walletinfo.Wallet)
        print ('4.3 ----4 -> Completed Blockchain deafault pause')
        sc_args = []
        sc_args.append(scname)
        BuildAndRun(sc_args, walletinfo.Wallet)
        Blockchain.Default().Resume()
        print ('5 ----5 -> .avm file created')
        args = []
        args.append("contract")
        print ('5 ----5.1 %s' %avmname)
        args.append(avmname)
        print ('5 ----5.1')
        args.append("0710")
        args.append("05")
        print ('5 ----5.2')
        args.append("True")
        print ('5 ----5.3')
        args.append("False")
        print ('6 ----5.4')
        args, from_addr = get_from_addr(args)
        function_code = LoadContract(args[1:])
        if function_code:
            contract_script = GatherContractDetails(function_code)
            print ('7 ----7 -> contract_script completed')          
            if contract_script is not None:
                tx, fee, results, num_ops = test_invoke(contract_script, walletinfo.Wallet, [], from_addr=from_addr)
                print ('8 ----8 -> test_invoke completed')   
                if tx is not None and results is not None:
                    print(
                        "\n-------------------------------------------------------------------------------------------------------------------------------------")
                    print("Test deploy invoke successful")
                    print("Total operations executed: %s " % num_ops)
                    print("Results:")
                    print([item.GetInterface() for item in results])
                    print("Deploy Invoke TX GAS cost: %s " % (tx.Gas.value / Fixed8.D))
                    print("Deploy Invoke TX Fee: %s " % (fee.value / Fixed8.D))
                    print(
                        "-------------------------------------------------------------------------------------------------------------------------------------\n")
                    result = InvokeContract(walletinfo.Wallet, tx, Fixed8.Zero(), from_addr=from_addr)
                    return
                else:
                    print("Test invoke failed")
                    print("TX is %s, results are %s" % (tx, results))
                    return "Test invoke failed"                   
    except Exception as e:

    # print("Pubkey %s" % key.PublicKey.encode_point(True))

        print ('Exception creating wallet: %s' % e)
        walletinfo.Wallet = None
        return returnvalue

    # Open and Replace Wallet
    # Echo it

    return {'post-body': returnvalue}


#
# Main method which starts everything up
#

def main():

    # Use TestNet

    settings.setup_testnet()

    # Setup the blockchain

    blockchain = LevelDBBlockchain(settings.chain_leveldb_path)
    Blockchain.RegisterBlockchain(blockchain)
    dbloop = task.LoopingCall(Blockchain.Default().PersistBlocks)
    dbloop.start(.1)
    NodeLeader.Instance().Start()
    

    # Disable smart contract events for external smart contracts

    settings.set_log_smart_contract_events(False)

    # Start a thread with custom code

    d = threading.Thread(target=custom_background_code)
    d.setDaemon(True)  # daemonizing the thread will kill it when the main thread is quit
    d.start()
    print("0 --- 0 -> STARTING")
    #Open the wallet and be ready
    try:
        global walletinfo
        walletinfo = PromptInterface()
        print("0 --- 0  -> walletinfo %s",walletinfo)
        print("0 --- 0  -> walletinfo created")
        wallet_path = '/home/ubuntu/nosforall'
        passwd = 'nosforallneeds'
        print("0 --- 0  -> About to Open wallet %s",wallet_path)
        password_key = to_aes_key(passwd)
        print("0 --- 0  -> About to Open wallet %s",password_key)
        #walletinfo.Wallet = UserWallet.Open(path=wallet_path,password=password_key)
        walletinfo.Wallet = UserWallet.Open(wallet_path,password_key)
        print("1 --- 1 -> Wallet Opened")
        walletinfo._walletdb_loop = task.LoopingCall(walletinfo.Wallet.ProcessBlocks)
        walletinfo._walletdb_loop.start(1)
        print("1 --- 1 -> Wallet Loop Started and is ready")
    except Exception as e:
        print ('Exception opening wallet: %s' % e)
        return 'Exception opening wallet.Please try manual deploying your SC. Also please shar issue with me @sharedmocha in Discord App.'

    # Hook up Klein API to Twisted reactor.
    # endpoint_description = "tcp:port=%s:interface=localhost" % API_PORT

    endpoint_description = 'tcp:port=%s' % API_PORT

    # If you want to make this service externally available (not only at localhost),
    # then remove the `interface=localhost` part:
    # endpoint_description = "tcp:port=%s" % API_PORT

    endpoint = endpoints.serverFromString(reactor, endpoint_description)
    endpoint.listen(Site(app.resource()))

    # Run all the things (blocking call)

    logger.info('Everything setup and running. Waiting for events...')
    reactor.run()
    logger.info('Shutting down.')


if __name__ == '__main__':
    main()
