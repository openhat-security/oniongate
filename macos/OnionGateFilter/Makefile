# Build the connection-filter system extension and the user-space activator.
# Loading on a Mac requires a Developer ID network-extension profile.
# Unsigned trees still compile so CI can syntax-check the Swift.

FILTER_ID = com.adamsiwiec.oniongate.filter
BUILD = build
FILTER_BIN = $(BUILD)/OnionGateFilter
CTL_BIN = $(BUILD)/oniongate-filter-ctl
SYSEX = $(BUILD)/$(FILTER_ID).systemextension

SWIFTC ?= xcrun swiftc
MACOS_MIN = 11.0
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
TRIPLE = x86_64-apple-macos$(MACOS_MIN)
else
TRIPLE = arm64-apple-macos$(MACOS_MIN)
endif
SWIFT_FLAGS = -O -target $(TRIPLE)

.PHONY: all clean bundle

all: bundle $(CTL_BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(FILTER_BIN): Classifier.swift FilterStateStore.swift FilterDataProvider.swift main.swift | $(BUILD)
	$(SWIFTC) $(SWIFT_FLAGS) \
		-framework Foundation -framework NetworkExtension -framework AppKit \
		-lbsm \
		-o $@ Classifier.swift FilterStateStore.swift FilterDataProvider.swift main.swift

$(CTL_BIN): ../OnionGateFilterCtl/main.swift | $(BUILD)
	$(SWIFTC) $(SWIFT_FLAGS) \
		-framework Foundation -framework SystemExtensions -framework NetworkExtension \
		-o $@ ../OnionGateFilterCtl/main.swift

bundle: $(FILTER_BIN)
	rm -rf $(SYSEX)
	mkdir -p $(SYSEX)/Contents/MacOS
	cp $(FILTER_BIN) $(SYSEX)/Contents/MacOS/OnionGateFilter
	cp Info.plist $(SYSEX)/Contents/Info.plist

clean:
	rm -rf $(BUILD)
