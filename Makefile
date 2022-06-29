# Compiler detials and flags
CXX = gcc
CXX_FLAGS = --std=c11 -g -Wall -O0 -DDEBUGGING 

# Library details and flags
LDFLAGS = -L../liboqs/build/lib
LDLIBS = -lcrypto -loqs -lm
INC_FLAGS = -I../liboqs/build/include -I./sig_stfl/xmss/external

# Executable details and flags
BUILD_DIR = build
SRC_DIR = sig_stfl/xmss/external

SOURCES = $(wildcard $(SRC_DIR)/*.c)
HEADERS = $(wildcard $(SRC_DIR)/*.h) 

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = $(BUILD_DIR)/test_fast $(BUILD_DIR)/test_multi $(BUILD_DIR)/test_struct # $(BUILD_DIR)/test_subkeys

tests: $(TESTS)

.PHONY: clean test

$(BUILD_DIR)/test_fast: tests/full_tester.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

$(BUILD_DIR)/test_struct: tests/new_structure_tester.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

$(BUILD_DIR)/test_subkeys: tests/subkeys_tester.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

$(BUILD_DIR)/test_multi: tests/multithreaded_tester.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CXX) $(CXX_FLAGS) -o $@ $(SOURCES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

clean:
	-$(RM) $(TESTS)
