# Compiler detials and flags
CXX 						:= gcc
CXX_FLAGS 					:= --std=c11 -g -Wall -Wextra -Wpedantic


# Executable details and flags
BUILD_DIR 					:= build
EXEC_DIR 					:= bin

# File extensions
SRC_EXT := c
HDR_EXT := h

# Stateful signatures directory 
SIG_STFL_DIR 				:= sig_stfl

# Library details and flags
LDFLAGS 					:= -L../liboqs/build/lib
LDLIBS 						:= -lcrypto -loqs -lm
INC_FLAGS 					:= -I../liboqs/build/include -I./sig_stfl/xmss/external

# XMSS implementation directory
XMSS_IMPL_DIR 				:= $(SIG_STFL_DIR)/xmss/external

# XMSS object directory
XMSS_OBJ_BUILD_DIR 			:= $(SIG_STFL_DIR)/xmss


# ------------------------------------------------------------------------------
# Do not edit below this line
# ------------------------------------------------------------------------------

# All Stateful signature files (Object / Secret Key definitions)
SIG_STFL_SRC_FILES 			:= $(wildcard $(SIG_STFL_DIR)/*.$(SRC_EXT))
SIG_STFL_HDR_FILES 			:= $(wildcard $(SIG_STFL_DIR)/*.$(HDR_EXT))

# XMSS Source code files
XMSS_IMPL_SRC_FILES 		:= $(wildcard $(XMSS_IMPL_DIR)/*.$(SRC_EXT))
XMSS_IMPL_HDR_FILES 		:= $(wildcard $(XMSS_IMPL_DIR)/*.$(HDR_EXT))

XMSS_OBJ_BUILD_SRC_FILES 	:= $(wildcard $(XMSS_OBJ_BUILD_DIR)/*.$(SRC_EXT))
XMSS_OBJ_BUILD_HDR_FILES 	:= $(wildcard $(XMSS_OBJ_BUILD_DIR)/*.$(HDR_EXT))

# Tests to performs
TESTS 						:= $(EXEC_DIR)/test_struct $(EXEC_DIR)/test_subkeys # $(BUILD_DIR)/test_fast $(BUILD_DIR)/test_multi  $(BUILD_DIR)/test_subkeys

tests: $(TESTS)

# Building the test executable(s)
$(EXEC_DIR)/test_struct: tests/new_structure_tester.c $(XMSS_IMPL_SRC_FILES) $(XMSS_IMPL_HDR_FILES) $(XMSS_OBJ_BUILD_SRC_FILES)  $(XMSS_OBJ_BUILD_HDR_FILES) $(SIG_STFL_SRC_FILES)  $(SIG_STFL_HDR_FILES) 
	$(CXX) $(CXX_FLAGS) -o $@ $(SIG_STFL_SRC_FILES) $(XMSS_IMPL_SRC_FILES) $(XMSS_OBJ_BUILD_SRC_FILES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

# Derving subkeys tester
$(EXEC_DIR)/test_subkeys: tests/subkeys_tester.c $(XMSS_IMPL_SRC_FILES) $(XMSS_IMPL_HDR_FILES) $(XMSS_OBJ_BUILD_SRC_FILES)  $(XMSS_OBJ_BUILD_HDR_FILES) $(SIG_STFL_SRC_FILES)  $(SIG_STFL_HDR_FILES) 
	$(CXX) $(CXX_FLAGS) -o $@ $(SIG_STFL_SRC_FILES) $(XMSS_IMPL_SRC_FILES) $(XMSS_OBJ_BUILD_SRC_FILES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

# Regular test executables (now defunct cause no secret_key.h and secret_key.c)
$(EXEC_DIR)/test_fast: tests/full_tester.c $(XMSS_IMPL_SRC_FILES) $(OBJS) $(XMSS_IMPL_HDR_FILES)
	$(CXX) $(CXX_FLAGS) -o $@ $(XMSS_IMPL_SRC_FILES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

$(EXEC_DIR)/test_multi: tests/multithreaded_tester.c $(XMSS_IMPL_SRC_FILES) $(OBJS) $(XMSS_IMPL_HDR_FILES)
	$(CXX) $(CXX_FLAGS) -o $@ $(XMSS_IMPL_SRC_FILES) $< $(LDLIBS) $(LDFLAGS) $(INC_FLAGS) 

clean:
	-$(RM) $(TESTS)

directories:
	mkdir $(BUILD_DIR) $(EXEC_DIR)

.PHONY: clean test directories