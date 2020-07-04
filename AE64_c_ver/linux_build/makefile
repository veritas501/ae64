ARCH=$(shell getconf LONG_BIT)
INCL=-I../deps/keystone/include -I../deps/cmdline
LIB=-L../deps/keystone/lib/linux-x${ARCH} -lkeystone
SRC=../AE64/ae64.cpp ../AE64/main.cpp ../AE64/bytes.cpp

ae64: 
	g++ --static ${SRC} ${INCL} ${LIB} -o ae64
	strip ae64
