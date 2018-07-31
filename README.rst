Deploying Smart Contracts onto nosNET using API


This github code allows anyone to deploy python smart contracts (or) compiled smart contract files such as . avm files onto nosNET using API instead of CLI(Command Line Interface)

Why use API ?


Today developers need to perform below steps for deploying smart contracts onto nosNet.

Download all required blockchain tools/softwares.
Setup blockchain node either on their local machine (or) cloud (or) docker
Sync blockchain node till it gets all the latest blocks.
Create wallet
Sync the wallet to 100%
Gather gas for deployment
Finally,compile and deploy smart contract and perform ‘Test Invoke’
all these steps require both time and system space.

This new API does the smart contract deployment by performing all the above steps. It does so by accepting your smart contract location and deploying it directly using a predefined wallet which has GAS. By using this API you can make smart contract deployments faster and easy.

**You can checkout the wallet being used by clicking here .
**Click here for wallet details



Checkout this article on how to use the API-


https://medium.com/@SharedMocha/deploy-smartcontracts-on-nosnet-using-api-dd5766d23f85

You can deploy this code on your local machine and run it yourself.
To deploy on Ubuntu 16.04 perform below steps
Step 1- Setup
Older Ubuntu versions (eg. 16.04)
For older Ubuntu versions you'll need to use an external repository like Felix Krull's deadsnakes PPA at https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa (read more here).

(The use of the third-party software links in this documentation is done at your own discretion and risk and with agreement that you will be solely responsible for any damage to your computer system or loss of data that results from such activities.)

apt-get install software-properties-common python-software-properties
add-apt-repository ppa:deadsnakes/ppa
apt-get update
apt-get install python3.6 python3.6-dev python3.6-venv python3-pip libleveldb-dev libssl-dev g

Step2- run below commands in your terminal/shell
rm -rf neo-python && git clone https://github.com/SharedMocha/neo-python.git && cd neo-python && python3.6 -m venv venv && source venv/bin/activate && pip install requests && pip install -e . && cd examples && export NEO_REST_API_TOKEN="123" && python3.6 smart-contract-rest-api.py
