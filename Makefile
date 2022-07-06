CXX = gcc
CXX_FLAGS = --std=c11 -g -Wall -O0 -DDEBUGGING
LDLIBS = -lcrypto -loqs -lm
BUILD_DIR = build
SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c secret_key.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h secret_key.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = $(BUILD_DIR)/test_fast $(BUILD_DIR)/test_multi # $(BUILD_DIR)/test_subkeys

tests: $(TESTS)

.PHONY: clean test

$(BUILD_DIR)/test_fast: tests/full_tester.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -L../liboqs/build/lib -I../liboqs/build/include -I.

$(BUILD_DIR)/test_subkeys: tests/subkeys_tester.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -L../liboqs/build/lib -I../liboqs/build/include -I.

$(BUILD_DIR)/test_multi: tests/multithreaded_tester.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -L../liboqs/build/lib -I../liboqs/build/include -I.

clean:
	-$(RM) $(TESTS)
