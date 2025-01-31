# Define the target binary and the capability you want to set
TARGET_BINARY = target/debug/fosr
CAPABILITY = cap_net_raw+ep  # Example: Allow binding to privileged ports (e.g., <1024)

# Default target
all: build setcap

run-online: all
	cargo run -- online

# Build the project with Cargo
build:
	cargo build

# Set capabilities on the resulting binary
setcap:
	sudo setcap $(CAPABILITY) $(TARGET_BINARY)

# Clean up
clean:
	cargo clean
