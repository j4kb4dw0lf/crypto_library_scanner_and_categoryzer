

# building :

```
docker build -t crypto-scanner .
```


# running the tool :

for example to analyze libssh as an external library and many major repos from github:

copying the release of libssh form their website under /ext said library can now be scanned


```
docker run -it --rm -v "$PWD/output:/app/output" -v "$PWD/repos:/app/repos" -v "$PWD/ext:/app/ext" crypto-scanner -ru https://github.com/openssl/openssl.git https://github.com/weidai11/cryptopp https://github.com/randombit/botan https://github.com/libssh2/libssh2 https://github.com/jedisct1/libsodium https://github.com/wolfSSL/wolfssl -elp /app/ext/libssh-(LIBSSH VERSION)
```

-elp   stands for external library paths and after there is to be put the patch of the library

-ru    stands for repo url
