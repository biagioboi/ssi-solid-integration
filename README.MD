# Solid Decentralized Auth

In this repo, we modify the code of Node Solid Serve (NSS) in order to support SSI for authentication procedure.

## Initialization
Clone the repository and move inside
```
git clone https://github.com/biagioboi/ssi-solid-integration
cd ssi-solid-integration
```

Install needed package
```
npm install
```

## Configuration
Before to startup the server it is necessary to configure public and private keys. If you notice in the file ```config.json```, you have the following fields that must be adapted to meet your files.
In the test path there is already a public key, but to use this project you have to create your own key pair.
```
"root": "path/to/ssi-solid-integration/data",
...
"sslKey": "path/to/ssi-solid-integration/test/keys/cert.pem",
"sslCert": "path/to/ssi-solid-integration/test/keys/key.pem",
```
Once configured the key you have to configure the ledger url, it is possible to use the same file for specifying the genesis ledger url.
```
"ledgerUrl": "localhost:9000/genesis",
```
## Start
Once we solver all the configurations matter, it is possible to start-up the server, which should start without any problem.
Start-up the server
```
npm run solid start
```


## Issues
### Issue 1: Unable to fetch libssl
Some possible issues can be raised with openssl when starting the server
```
Error: dlopen(indynodejs.node, 0x0001): Library not loaded: /usr/local/opt/openssl/lib/libssl.1.0.0.dylib
Referenced from: <C67E94B8-4256-34B1-8B9C-2B5C49B87226> /usr/local/Cellar/libindy/1.16.0/lib/libindy.dylib
Reason: tried: '/usr/local/opt/openssl/lib/libssl.1.0.0.dylib' (no such file), '/System/Volumes/Preboot/Cryptexes/OS/usr/local/opt/openssl/lib/libssl.1.0.0.dylib' (no such file), '/usr/local/opt/openssl/lib/libssl.1.0.0.dylib' (no such file), '/usr/local/lib/libssl.1.0.0.dylib' (no such file), '/usr/lib/libssl.1.0.0.dylib' (no such file, not in dyld cache), '/usr/local/Cellar/openssl@3/3.2.0/lib/libssl.1.0.0.dylib' (no such file), '/System/Volumes/Preboot/Cryptexes/OS/usr/local/Cellar/openssl@3/3.2.0/lib/libssl.1.0.0.dylib' (no such file), '/usr/local/Cellar/openssl@3/3.2.0/lib/libssl.1.0.0.dylib' (no such file), '/usr/local/lib/libssl.1.0.0.dylib' (no such file), '/usr/lib/libssl.1.0.0.dylib' (no such file, not in dyld cache)
```
### Repair 1: Install libssl and point it
The following resolution works on MacOS, but can be easily adapted in order to work with other OS. Install libssl and refer to it.
```
brew install rbenv/tap/openssl@1.0
ln -sfn /usr/local/Cellar/openssl@1.0/1.0.2t /usr/local/opt/openssl
```