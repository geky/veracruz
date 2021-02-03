# This makefile is used within the docker image generated by docker/Dockerfile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
 
.PHONY: all sdk test_cases sgx-durango-test trustzone-durango-test sgx sgx-enclaves sgx-bin trustzone trustzone-enclaves trustzone-bin sgx-sinaloa-test sgx-sinaloa-performance sgx-veracruz-test sgx-psa-attestation tz-psa-attestationtrustzone-sinaloa-test-setting  trustzone-veracruz-test-setting trustzone-env sgx-env tlaxcala trustzone-test-env clean clean-cargo-lock fmt

 
WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"
OPTEE_DIR_SDK ?= /work/rust-optee-trustzone-sdk/
AARCH64_OPENSSL_DIR ?= /work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0/build/openssl-1.0.2s/
AARCH64_GCC ?= $(OPTEE_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-gcc
SGX_RUST_FLAG ?= "-L/work/sgxsdk/lib64 -L/work/sgxsdk/sdk_libs"
NITRO_RUST_FLAG ?= ""
 
all:
	@echo $(WARNING_COLOR)"Please explicitly choose a target."$(RESET_COLOR)

# Build all of the SDK and examples
sdk:
	$(MAKE) -C sdk

# Generate all test policy
test_cases: sdk
	$(MAKE) -C test-collateral

# Test durango for sgx, due to the use of a mocked server with a fixed port, these tests must run in a single thread
sgx-durango-test: sgx test_cases 
	cd durango && RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --lib --features "mock sgx" -- --test-threads=1

# Test durango for sgx, due to the use of a mocked server with a fixed port, these tests must run in a single thread
trustzone-durango-test: trustzone test_cases
	cd durango && cargo test --lib --features "mock tz" -- --test-threads=1

# Compile for sgx
# offset the CC OPENSSL_DIR, which might be used in compiling trustzone
sgx: sdk sgx-enclaves sgx-durango sgx-bin

sgx-enclaves: sgx-env
	cd mexico-city-bind && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build
	cd trustzone-root-enclave-bind && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build

sgx-durango: sgx-enclaves sgx-env
	cd durango && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build --lib --features sgx

sgx-bin: sgx-enclaves sgx-env
	mkdir -p bin
	# TODO do we really need SGX flag for tabasco?
	cd tabasco-cli && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build --features sgx
	cd sinaloa-cli && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build --features sgx
	cd durango-cli && cargo build
	cp tabasco-cli/target/debug/tabasco bin/tabasco
	# TODO remove relative path to enclave .so in Sinaloa?
	cp sinaloa-cli/target/debug/sinaloa bin/sinaloa
	cp durango-cli/target/debug/durango bin/durango

nitro: sdk
	pwd
	RUSTFLAGS=$(NITRO_RUST_FLAG) $(MAKE) -C mexico-city nitro
	RUSTFLAGS=$(NITRO_RUST_FLAG) $(MAKE) -C nitro-root-enclave
	RUSTFLAGS=$(NITRO_RUST_FLAG) $(MAKE) -C nitro-root-enclave-server

# Compile for trustzone, note: source the rust-optee-trustzone-sdk/environment first, however assume `unset CC`.
trustzone: sdk trustzone-enclaves trustzone-durango trustzone-bin

trustzone-enclaves: trustzone-env
	$(MAKE) -C mexico-city trustzone CC=$(AARCH64_GCC)
	$(MAKE) -C sgx-root-enclave trustzone

trustzone-durango: trustzone-enclaves trustzone-env
	cd durango && RUSTFLAGS=$(SGX_RUST_FLAG) cargo build --lib --features tz

trustzone-bin: trustzone-env
	mkdir -p bin
	# TODO do we really need SGX flag for tabasco?
	cd tabasco-cli && cargo build --target aarch64-unknown-linux-gnu --features tz
	cd sinaloa-cli && cargo build --target aarch64-unknown-linux-gnu --features tz
	cd durango-cli && cargo build
	cp tabasco-cli/target/debug/tabasco bin/tabasco
	cp sinaloa-cli/target/debug/sinaloa bin/sinaloa
	cp durango-cli/target/debug/durango bin/durango

sgx-sinaloa-test: sgx test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features sgx \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test test_debug --features sgx  -- --ignored --test-threads=1

sgx-sinaloa-test-dry-run: sgx test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features sgx --no-run 

sgx-sinaloa-performance: sgx test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test test_performance_ --features sgx -- --ignored 

sgx-veracruz-test-dry-run: sgx test_cases
	cd veracruz-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features sgx --no-run

sgx-veracruz-test: sgx test_cases
	cd veracruz-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features sgx 

sgx-psa-attestation: sgx-env
	cd psa-attestation && cargo build --features sgx

tz-psa-attestation: trustzone-env
	cd psa-attestation && cargo build --target aarch64-unknown-linux-gnu --features tz

trustzone-sinaloa-test: trustzone test_cases trustzone-test-env
	cd sinaloa-test \
		&& export OPENSSL_DIR=$(AARCH64_OPENSSL_DIR) \
		&& cargo test --target aarch64-unknown-linux-gnu --no-run --features tz -- --test-threads=1 \
		&& ./cp-sinaloa-test-tz.sh
	chmod u+x run_sinaloa_test_tz.sh
	./run_sinaloa_test_tz.sh

trustzone-veracruz-test: trustzone test_cases trustzone-test-env
	cd veracruz-test \
		&& export OPENSSL_DIR=$(AARCH64_OPENSSL_DIR) \
		&& cargo test --target aarch64-unknown-linux-gnu --no-run --features tz -- --test-threads=1 \
		&& ./cp-veracruz-tz.sh
	chmod u+x run_veracruz_test_tz.sh
	./run_veracruz_test_tz.sh

trustzone-test-env: tz_test.sh run_tz_test.sh
	chmod u+x $^

nitro-sinaloa-test: nitro test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(NITRO_RUST_FLAG) cargo test --features nitro \
		&& RUSTFLAGS=$(NITRO_RUST_FLAG) cargo test test_debug --features nitro,debug -- --ignored --test-threads=1
	cd sinaloa-test \
		&& ./nitro-terminate.sh
	cd ./sinaloa-test \
		&& ./nitro-ec2-terminate_root.sh

nitro-sinaloa-test-dry-run: nitro test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(NITRO_RUST_FLAG) cargo test --features sgx --no-run

nitro-sinaloa-performance: nitro test_cases
	cd sinaloa-test \
		&& RUSTFLAGS=$(NITRO_RUST_FLAG) cargo test test_performance_ --features nitro -- --ignored
	cd sinaloa-test \
		&& ./nitro-terminate.sh
	cd ./sinaloa-test \
		&& ./nitro-ec2-terminate-root.sh

nitro-veracruz-test-dry-run: nitro test_cases
	cd veracruz-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features nitro --no-run

nitro-veracruz-test: nitro test_cases
	cd veracruz-test \
		&& RUSTFLAGS=$(SGX_RUST_FLAG) cargo test --features nitro
	cd sinaloa-test \
		&& ./nitro-terminate.sh
	cd ./sinaloa-test \
		&& ./nitro-ec2-terminate_root.sh

nitro-psa-attestation:
	cd psa-attestation && cargo build --features nitro

trustzone-env:
	unset CC
	rustup target add aarch64-unknown-linux-gnu arm-unknown-linux-gnueabihf
	rustup component add rust-src
	chmod u+x tz_test.sh

sgx-env:
	unset CC

clean:
	cd mexico-city-bind && cargo clean 
	cd trustzone-root-enclave-bind && cargo clean
	cd psa-attestation && cargo clean
	cd proxy-attestation-server && cargo clean
	cd session-manager && cargo clean
	cd veracruz-utils && cargo clean
	cd sinaloa-test && cargo clean
	cd veracruz-test && cargo clean
	cd nitro-root-enclave-server && cargo clean
	$(MAKE) clean -C mexico-city
	$(MAKE) clean -C sgx-root-enclave
	$(MAKE) clean -C sinaloa
	$(MAKE) clean -C test-collateral 
	$(MAKE) clean -C trustzone-root-enclave
	$(MAKE) clean -C sdk
	$(MAKE) clean -C nitro-root-enclave
	cd tabasco-cli && cargo clean
	cd sinaloa-cli && cargo clean
	cd durango-cli && cargo clean
	rm -rf bin

# NOTE: this target deletes ALL cargo.lock.
clean-cargo-lock:
	$(MAKE) clean -C sdk
	rm -f $(addsuffix /Cargo.lock,session-manager execution-engine colima durango sgx-root-enclave mexico-city-bind mexico-city psa-attestation sinaloa-test sinaloa trustzone-root-enclave-bind trustzone-root-enclave proxy-attestation-server veracruz-test veracruz-util)

fmt:
	cd session-manager && cargo fmt
	cd execution-engine && cargo fmt
	cd colima && cargo fmt
	cd durango && cargo fmt
	cd sgx-root-enclave && cargo fmt
	cd mexico-city && cargo fmt
	cd psa-attestation && cargo fmt
	cd sinaloa-test && cargo fmt
	cd sinaloa && cargo fmt
	cd veracruz-test && cargo fmt
	cd veracruz-utils && cargo fmt
	cd trustzone-root-enclave && cargo fmt
	cd proxy-attestation-server && cargo fmt
	$(MAKE) -C sdk fmt
	cd tabasco-cli && cargo fmt
	cd sinaloa-cli && cargo fmt
	cd durango-cli && cargo fmt
