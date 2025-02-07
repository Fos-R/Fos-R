TARGET_BINARY = target/debug/fosr

debug:
	cargo build
	sudo setcap cap_net_bind_service+ep $(TARGET_BINARY)
	sudo setcap cap_net_raw+ep $(TARGET_BINARY)

release:
	cargo build --release
	sudo setcap cap_net_bind_service+ep $(TARGET_BINARY)
	sudo setcap cap_net_raw+ep $(TARGET_BINARY)
