
# RUNNING

```
docker build -t crypto-scanner .

docker run --rm -v "/home/jakbadwolf/Desktop/trial and error/crypto-scanner/output:/app/output" -v "/home/jakbadwolf/Desktop/trial and error/crypto-scanner/repos:/app/repos" crypto-scanner https://github.com/openssl/openssl.git https://github.com/weidai11/cryptopp https://github.com/randombit/botan https://github.com/libssh2/libssh2 https://github.com/jedisct1/libsodium https://github.com/wolfSSL/wolfssl
```