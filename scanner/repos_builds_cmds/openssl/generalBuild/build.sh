./Configure enable-fips enable-ktls enable-asan enable-ubsan enable-crypto-mdebug enable-crypto-mdebug-backtrace enable-unit-test enable-buildtest-c++ enable-external-tests enable-weak-ssl-ciphers enable-trace enable-ssl-trace enable-ec_nistp_64_gcc_128 enable-md2 enable-rc5 enable-rfc3779 enable-camellia enable-seed enable-rmd160 enable-idea enable-mdc2 enable-rc2 enable-rc4 enable-bf enable-cast enable-whirlpool threads shared no-sctp
make clean
make -j4 all
