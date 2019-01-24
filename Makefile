default:
	./scripts/build.sh

	export CPATH=.:/home/michi/projects/wabt/wasm2c/:$CPATH
	cp -f /home/michi/projects/wabt/wasm2c/wasm-rt-impl* .

	wasm2c node/runtime/wasm/target/wasm32-unknown-unknown/release/node_runtime.compact.wasm -o node_runtime.c

	gcc -fPIC -rdynamic -shared -o node_runtime node_runtime.c wasm-rt-impl.c

	cp node_runtime /home/michi/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/

all:
	gcc -fPIC -rdynamic -shared -o libruntime_test.so runtime_test.c wasm-rt-impl.c
	gcc -fPIC -rdynamic -shared -o libnode_runtime.so node_runtime.c wasm-rt-impl.c
	gcc -fPIC -rdynamic -shared -o libsubstrate_test_runtime.so substrate_test_runtime.c wasm-rt-impl.c

	cp lib* target/release/deps/
