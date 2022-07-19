CC = /usr/bin/gcc
CFLAGS = -Wall -O3 -Wextra -Wpedantic
LDLIBS = -loqs -lcrypto 
OPENSSL = -L/opt/homebrew/opt/openssl@1.1/lib -I/opt/homebrew/opt/openssl@1.1/include

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c nist.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h nist_params.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/test_fast test/nist_xmss_test test/nist_xmssmt_test

tests: $(TESTS)

.PHONY: clean test

test/test_fast: test/test.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) $(OPENSSL)

test/nist_xmss_test: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=0 -DLEVEL=0 $(OPENSSL)
	test/nist_xmss_test

test/nist_xmssmt_test: test/nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -DXMSSMT=1 -DLEVEL=0 $(OPENSSL)
	test/nist_xmssmt_test

clean:
	-$(RM) $(TESTS)
