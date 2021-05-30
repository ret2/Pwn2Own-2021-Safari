// need an onmessage handler so we can unblock the thread to trigger rop
onmessage = function(data) {
}

// say we spawned
postMessage(true)
