## Building

`python3 gen_wasm.py` is used to generate the wasm module, which will output a `rets.wasm` file

The script automates finding JavaScriptCore symbol/gadget offsets, which will need to be specified the first time with
`python3 gen_wasm.py -offs prod`. This will determine offsets (using lldb, so it will probably ask for your password/permission) and write them out to a file for use on subsequent runs.
`prod` uses the system-wide shared cache, you can also specify a path to a different JavaScriptCore dylib.

## Running

Use an http server like `python3 -m http.server <port>` then navigate to `localhost:<port>` in a vulnerable version of Safari.
The default shellcode stub will connect back to localhost on port 1337 to receive a 2nd stage shellcode.

There is a server that can serve a second stage shellcode blob with `python3 stage2_server.py <path to shellcode blob>`
