export CXXFLAGS="-DCRYPTOPP_DISABLE_ASM"
make clean
make -j$(sysctl -n hw.ncpu)
