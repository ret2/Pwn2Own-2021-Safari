function print(s) {
    postMessage(s.toString())
}

// say we spawned
postMessage(false)

let inst = null
function recur(depth) {
    try {
        recur(depth+1)
        return
    } catch(e) {}
    if (inst === null)
        return
    try {
        inst.exports.rets()
    } catch(e) {
        if (e.name === "RangeError")
            throw e
    }
}

for (let i = 0; i < 10000; i++)
    recur(0)

onmessage = function(evt) {
    let mod = evt.data
    let mem = new WebAssembly.Memory({initial:1, maximum:1})

    inst = new WebAssembly.Instance(mod, {e:{mem:mem}})

    //this is for custom patched jsc to emulate bug
    try { WebAssembly.Module.setNumCalleeLocals(mod, 0, 0) } catch(e) {}

    recur(0)
    postMessage(true)
}
