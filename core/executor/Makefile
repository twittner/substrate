default:
	RUSTFLAGS=-Awarnings cargo test --color always --release  -- --nocapture wasm_executor::tests::blake2_256_should_work 2>&1

gdb:
	export LD_LIBRARY_PATH=.:/home/michi/projects/substrate/target/release/deps/:$LD_LIBRARY_PATH
	export LDPATH=.:/home/michi/projects/substrate/target/release/deps/:$LDPATH
	gdb --args /home/michi/projects/substrate/target/release/deps/substrate_executor-0301c8f46a473b84 --nocapture 'wasm_executor::tests::returning_should_work'
