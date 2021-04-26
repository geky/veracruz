# Project name/paths, used for docker image
TARGET ?= mini-durango
DOCKER_IMAGE ?= $(TARGET)
DOCKER_CONTAINER ?= $(TARGET)
DOCKER_ROOT ?= $(abspath $(firstword $(MAKEFILE_LIST))/..)

ELF_PATH ?= /zephyr-workspace/$(TARGET)/build/zephyr/zephyr.elf

# QEMU configuration
QEMU ?= /opt/zephyr-sdk-0.11.4/sysroots/x86_64-pokysdk-linux/usr/bin/qemu-system-arm
QEMU_FLAGS += -cpu cortex-m3
QEMU_FLAGS += -machine lm3s6965evb
#QEMU_FLAGS += -machine mps2-an385
#QEMU_FLAGS += -m 1M
QEMU_FLAGS += -nographic
QEMU_FLAGS += -vga none
QEMU_FLAGS += -net none
QEMU_FLAGS += -pidfile qemu.pid
QEMU_FLAGS += -chardev stdio,id=con,mux=on
QEMU_FLAGS += -serial chardev:con
QEMU_FLAGS += -mon chardev=con,mode=readline
#QEMU_FLAGS += -icount shift=6,align=off,sleep=off
QEMU_FLAGS += -rtc clock=vm
#QEMU_FLAGS += -nic tap,model=stellaris,script=no,downscript=no,ifname=zeth
QEMU_FLAGS += -serial unix:/tmp/slip.sock
QEMU_FLAGS += -kernel $(ELF_PATH)
QEMU_FLAGS += -semihosting

GDB ?= /opt/zephyr-sdk-0.11.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-gdb-no-py


# Run in docker
.PHONY: docker
docker: Dockerfile
	$(strip docker build \
		--build-arg TARGET=$(TARGET) \
		--build-arg USER=$(USER) \
		--build-arg UID=$(UID) \
		-t $(DOCKER_IMAGE) -f $< .)
	$(strip docker run -it --rm \
		-v $(DOCKER_ROOT):/zephyr-workspace/$(TARGET) \
		--cap-add=NET_ADMIN --device /dev/net/tun:/dev/net/tun \
		--name $(DOCKER_CONTAINER) \
		$(DOCKER_IMAGE) bash -c "./slip-setup.sh ; bash")

# Zephyr west commands
.PHONY: update
update:
	west update

# TODO move these into west?
# Generate policy.h/c
policy.h policy.c: policy_to_header.py
policy.h policy.c: policy.json client_cert.pem client_key.pem
	$(strip ./policy_to_header.py $< \
		--identity=$(word 2,$^) \
		--key=$(word 3,$^) \
		--header=policy.h \
		--source=policy.c)

# Generate transport_protocol.pb.h/c
transport_protocol.pb.h transport_protocol.pb.c: \
		transport_protocol.proto transport_protocol.options
	./nanopb/generator/nanopb_generator.py $< -f $(word 2,$^)

.DEFAULT_GOAL :=
.PHONY: build
build: policy.h policy.c
build: transport_protocol.pb.h transport_protocol.pb.c
build:
	west build -p auto -b qemu_cortex_m3

.PHONY: clean
clean:
	rm -rf policy.h policy.c
	rm -rf transport_protocol.pb.h transport_protocol.pb.c
	rm -rf build

.PHONY: rom_report
rom_report: build
	west build -t rom_report

.PHONY: ram
ram_report: build
	west build -t ram_report

# QEMU
.PHONY: run
run: build
	$(QEMU) $(QEMU_FLAGS)

.PHONY: debug
debug: build
	$(QEMU) -gdb tcp::1234 -S $(QEMU_FLAGS) & $(GDB) $(ELF_PATH) -ex 'target remote localhost:1234'
	
.PHONY: debug-after
debug-after: build
	$(QEMU) -gdb tcp::1234 $(QEMU_FLAGS) & sleep 2 ; $(GDB) $(ELF_PATH) -ex 'target remote localhost:1234'

# Network tracing
.PHONY: tcpdump
tcpdump:
	tcpdump -i tap0 &
	sleep 0.1
