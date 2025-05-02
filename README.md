
# RUNNING

```
docker build -t crypto-scanner .
```

after copying the release of libssh form their website and putting it under (PATH TO FOLDER)/crypto-scanner/ext said library can now be scanned too

```
docker run -it --rm -v "(PATH TO FOLDER)/crypto-scanner/output:/app/output" -v "(PATH TO FOLDER)/crypto-scanner/repos:/app/repos" -v "(PATH TO FOLDER)/crypto-scanner/ext:/app/ext" crypto-scanner -ru https://github.com/openssl/openssl.git https://github.com/weidai11/cryptopp https://github.com/randombit/botan https://github.com/libssh2/libssh2 https://github.com/jedisct1/libsodium https://github.com/wolfSSL/wolfssl -elp /app/ext/libssh-0.11.0
```
