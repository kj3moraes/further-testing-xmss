CC = /usr/bin/gcc
CFLAGS = -Wall -O3 -Wextra -Wpedantic
LDLIBS = -loqs -lcrypto -lpthread
OPENSSL = -L/opt/homebrew/opt/openssl@1.1/lib -I/opt/homebrew/opt/openssl@1.1/include
LEVEL = 0
POSIX_THREAD = 1

SOURCES = thread_wrapper.c params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c nist.c
HEADERS = thread_wrapper.h params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h nist_params.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

MULTI_THREAD = test/nist_xmss_test_mp test/nist_xmssmt_test_mp
SINGLE_THREAD = test/nist_xmss_test test/nist_xmssmt_test
TESTS = test/test_fast

all: $(MULTI_THREAD) $(SINGLE_THREAD)
mp: $(MULTI_THREAD)
sp: $(SINGLE_THREAD)
tests: $(TESTS)

.PHONY: clean test

test/test_fast: test/test.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) $(OPENSSL)

test/nist_xmss_test: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=0 -DLEVEL=$(LEVEL) -DRANDOM=0  $(OPENSSL)	
	test/nist_xmss_test

test/nist_xmss_test_mp: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=0 -DLEVEL=$(LEVEL) -DRANDOM=0  -DMP=1 -DPOSIX_THREAD=$(POSIX_THREAD) $(OPENSSL)	
	test/nist_xmss_test_mp

test/nist_xmssmt_test: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=1 -DLEVEL=$(LEVEL) -DRANDOM=0  $(OPENSSL)
	test/nist_xmssmt_test

test/nist_xmssmt_test_mp: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=1 -DLEVEL=$(LEVEL) -DRANDOM=0  -DMP=1 -DPOSIX_THREAD=$(POSIX_THREAD) $(OPENSSL)
	test/nist_xmssmt_test_mp

clean:
	-$(RM) $(TESTS) $(MULTI_THREAD) $(SINGLE_THREAD)
