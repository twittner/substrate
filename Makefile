default:
	echo "1"
	gcc -fPIC -rdynamic -shared -o libruntime_test.so runtime_test.c wasm-rt-impl.c
	echo "2"
	gcc -fPIC -rdynamic -shared -o libnode_runtime.so node_runtime.c wasm-rt-impl.c
	echo "3"
	gcc -fPIC -rdynamic -shared -o libsubstrate_test_runtime.so substrate_test_runtime.c wasm-rt-impl.c

	echo "4"
	cp -f lib* target/release/deps/

cross_compile:
	./scripts/build.sh

	export CPATH=.:/home/michi/projects/wabt/wasm2c/:$CPATH
	cp -f /home/michi/projects/wabt/wasm2c/wasm-rt-impl* .

	wasm2c node/runtime/wasm/target/wasm32-unknown-unknown/release/node_runtime.compact.wasm -o node_runtime.c

	gcc -fPIC -rdynamic -shared -o node_runtime node_runtime.c wasm-rt-impl.c

	cp node_runtime /home/michi/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/

read:
	readelf -Ws libruntime_test.so

test:
	gcc -fPIC -rdynamic -shared -o libruntime_test.so runtime_test.c wasm-rt-impl.c &&
		rm ./target/release/deps/libruntime_test.so &&
		cp libruntime_test.so target/release/deps/

	 RUST_BACKTRACE=1 RUSTFLAGS=-Awarnings cargo test --color always --release -- --nocapture wasm_executor::tests::returning_should_work 2>&1 | bat
