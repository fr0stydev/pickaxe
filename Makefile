# Makefile

CC := x86_64-w64-mingw32-gcc
STRIP := x86_64-w64-mingw32-strip
MCS := mcs
NM := x86_64-w64-mingw32-nm
SMA_REF ?=

OUT := _bin
BOF := $(OUT)/powerpick-probe.x64.o
PROBE := $(OUT)/PowerPickProbe.exe

CFLAGS := -Os -w -Wno-incompatible-pointer-types -I include

.PHONY: all bof managed verify clean

all: bof managed verify

$(OUT):
	mkdir -p $(OUT)

bof: $(BOF)

$(BOF): native/powerpick_probe.c include/powerpick_probe.h include/beacon.h | $(OUT)
	$(CC) $(CFLAGS) -c native/powerpick_probe.c -o $(BOF)
	$(STRIP) --strip-unneeded $(BOF)

managed: $(PROBE)

$(PROBE): managed/PowerPickProbe.cs | $(OUT)
	@test -n "$(SMA_REF)" || (echo "SMA_REF must point to System.Management.Automation.dll" >&2; exit 1)
	@test -f "$(SMA_REF)" || (echo "SMA_REF does not exist: $(SMA_REF)" >&2; exit 1)
	$(MCS) -sdk:4 -platform:anycpu -optimize+ -target:exe \
		-out:$(PROBE) -r:"$(SMA_REF)" -r:System.Core \
		managed/PowerPickProbe.cs

verify: $(BOF) $(PROBE)
	@file $(BOF) $(PROBE)
	@$(NM) $(BOF) | grep -Eq ' T go$$'
	@! strings $(BOF) | grep -Eiq 'patch(AMSI|ETW)|AmsiScanBuffer|EtwEventWrite'
	@! grep -REiq 'patch(AMSI|ETW)|AmsiScanBuffer|EtwEventWrite|ExecutionPolicy' native include managed

clean:
	rm -rf $(OUT)
