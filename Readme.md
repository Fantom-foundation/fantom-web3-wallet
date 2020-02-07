# Web3 Functions

# Install 
`npm i web3-functions`.

# Get the balance of Wallet

    const getBalance = async (address) => {
    const res = await web3.eth.getBalance(address);
    return res;
    }

# For checking Web3 Provider is available or not

    const isConnected = async () => {
    if (!web3) return false;
    return !!await web3.eth.getNodeInfo();
    }

# Set Web3 Provider

    const setProvider = async () => {
    const prov = new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || '');
    if (!web3) {
    web3 = new Web3(prov);
    } else {
    web3.setProvider(prov);
    }
    }

# Get KeyStore file using Private Key

    const getKeystore = (privateKey, password) => {
    if (!web3) throw new Error('not inialized');

        return web3.eth.accounts.encrypt(privateKey, password);

    };

# Get info on delegator

    const getDelegate = (from, delegateAddress, sfc) => {
    return new Promise(resolve => {
    sfc.methods.delegations(delegateAddress).call({ from }, function (error, result) {
    if (!error) resolve(result);
    console.log(error, 'errorerror getDelegate');
    });
    });
    }

# Validate KeyStore

    const validateKeystore = (keystore, password) => {
    if (!web3) throw new Error('not inialized');

        return web3.eth.accounts.decrypt(keystore, password);

    };

# Get Private Key from KeyStore and Password

    const getPrivateKey = (keystore, password) =>
    new Promise(resolve =>
    keythereum.recover(password, keystore, dataRes => {
    resolve(dataRes instanceof Buffer ? EthUtil.bufferToHex(dataRes) : null);
    })
    );

# Get estimationfee for transactions and Staking (in Web)

    const estimateFee = async ({ from, to, value, memo }) => {
    const gasPrice = await web3.eth.getGasPrice();
    const gasLimit = await web3.eth.estimateGas({
    from,
    to,
    value: Web3.utils.toHex(Web3.utils.toWei(value, 'ether')),
    data: Web3.utils.asciiToHex(memo)
    });
    const fee = Web3.utils.fromWei(
    BigInt(gasPrice.toString())
    .multiply(BigInt(gasLimit.toString()))
    .toString()
    );
    return fee;
    }

# Get delegation pending rewards after staking

    const getDelegationPendingRewards = async (from, delegateAddress) => {
    const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
    const sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
    const info = await Promise.all([
    getCurrentEpoch(from, sfc),
    getDelegate(from, delegateAddress, sfc) || {}
    ]);
    const maxEpochs = Number(info[0]) - 1;
    const fromEpoch = info[1].paidUntilEpoch;
    return new Promise(resolve => {
    sfc.methods
    .calcDelegationRewards(delegateAddress, fromEpoch, maxEpochs)
    .call({ from }, function (error, result) {
    if (result) {
    resolve({
    pendingRewards: parseFloat(result['0']) / Math.pow(10, 18),
    data: info[1]
    });
    } else {
    resolve({ pendingRewards: 0, data: info[1] });
    }
    });
    });
    }

# Get epoch for unstake FTM

    const getCurrentEpoch = (from, sfc) => {
    return new Promise(resolve => {
    sfc.methods.currentEpoch().call({ from }, function (error, result) {
    if (!error) {
    resolve(result);
    }
    console.log(error, 'errorerror getCurrentEpoch');
    });
    });
    }

# Restore Wallet using Private key

    const restoreWallet = async (privateKey) => {
    const wallet = web3.eth.accounts.privateKeyToAccount(privateKey);
    return wallet;
    }

# Get TransactionFee (Mobile)

    const getTransactionFee = async (gasLimit) => {
    const gasPrice = await web3.eth.getGasPrice();
    // const gasLimit = 200000;
    const fee = Web3.utils.fromWei(
    BigInt(gasPrice.toString())
    .multiply(BigInt(gasLimit.toString()))
    .toString()
    );
    return fee;
    }

# Delegate stake

    const delegateStake = ({ amount, publicKey, privateKey, validatorId, isWeb = false }) => {
    console.log(amount, publicKey, privateKey, validatorId, '**\*\***8amount, publicKey, privateKey, validatorId');

        const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));

        const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
        return transfer({
            from: publicKey,
            to: '0xfc00face00000000000000000000000000000000',
            value: amount,
            memo: web3Sfc.methods.createDelegation(validatorId).encodeABI(),
            privateKey,
            gasLimit: 200000,
            web3Delegate: web3,
            isWeb
        });

        }

# Unstake your staked amount

    const delegateUnstake = async (publicKey, privateKey) => {
    const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
    const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
    return transfer({
    from: publicKey,
    to: '0xfc00face00000000000000000000000000000000',
    value: '0',
    memo: web3Sfc.methods.prepareToWithdrawDelegation().encodeABI(),
    privateKey,
    gasLimit: 200000,
    web3Delegate: web3

# Transfer FTM

    const transfer = async ({
    from,
    to,
    value,
    memo = '',
    privateKey,
    gasLimit = 44000,
    web3Delegate = ''
    }) => {
    const useWeb3 = web3Delegate || web3;
    const nonce = await useWeb3.eth.getTransactionCount(from);
    const gasPrice = await useWeb3.eth.getGasPrice();
    const rawTx = {
    from,
    to,
    value: Web3.utils.toHex(Web3.utils.toWei(value, 'ether')),
    gasLimit: Web3.utils.toHex(gasLimit),
    gasPrice: Web3.utils.toHex(gasPrice),
    nonce: Web3.utils.toHex(nonce),
    data: `0x${memo}`
    };
    const privateKeyBuffer = EthUtil.toBuffer(privateKey);
    const tx = new Tx(rawTx);
    tx.sign(privateKeyBuffer);
    const serializedTx = tx.serialize();
    const res = await useWeb3.eth.sendSignedTransaction(`0x${serializedTx.toString('hex')}`);
    return res;
    }});
    }

# Withdrawing FTM which you have unstaked

    const withdrawDelegateAmount = async (publicKey, privateKey) => {
    const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
    const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
    return transfer({
    from: publicKey,
    to: '0xfc00face00000000000000000000000000000000',
    value: '0',
    memo: web3Sfc.methods.withdrawDelegation().encodeABI(),
    privateKey,
    gasLimit: 200000,
    web3Delegate: web3
    });
    }

# Get account information i.e transaction details

    const getAccount = async (address) => {
    return await fetch(`${REACT_APP_API_URL_FANTOM}api/v1/get-account?address=${address}`);
    }

# Get Keys from Mnemonic

    const mnemonicToKeys = async (mnemonic) => {
    const seed = await Bip39.mnemonicToSeed(mnemonic);
    const root = Hdkey.fromMasterSeed(seed);

    const addrNode = root.derive("m/44'/60'/0'/0/0");
    const pubKey = EthUtil.privateToPublic(addrNode._privateKey);
    const addr = EthUtil.publicToAddress(pubKey).toString('hex');
    const publicAddress = EthUtil.toChecksumAddress(addr);
    const privateKey = EthUtil.bufferToHex(addrNode._privateKey);

    return { publicAddress, privateKey };

    };

# Get Keys from Private Key

    const privateKeyToKeys = (privateKey) => {
    const privateKeyBuffer = EthUtil.toBuffer(privateKey);

        const pubKey = EthUtil.privateToPublic(privateKeyBuffer);
        const addr = EthUtil.publicToAddress(pubKey).toString('hex');
        const publicAddress = EthUtil.toChecksumAddress(addr);

        return { publicAddress, privateKey };

    };
