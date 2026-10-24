# StructScan WinDbg Extension (v4.0)

**StructScan** is a high-performance extension plugin for the WinDbg debugger (`dbgeng.dll`), designed for **automated reconstruction of undocumented data structures** (such as opaque kernel structures lacking private PDB symbols, custom driver objects, `ntdsai!gAnchor`, `nt!_OBJECT_TYPE`, etc.) and instant synthesis of ready-to-use C/C++ header definitions.

Version **v4.0** features high-speed virtual memory analysis (`ReadVirtual`), automated C/C++ header synthesis (`emit`), Shannon entropy profiling (`entropy`), Bayesian field classification, multi-instance cross-referencing via `LIST_ENTRY` chains (`list`), advanced kernel-level Use-After-Free lifetime analysis (`!uaf`), and cross-architecture Control Flow Transfer (CFT) tracing (`!cft`).

---

## 🚀 Installation & WinDbg Usage

### 1. Load the Plugin into WinDbg:
```text
0: kd> .load C:\Tools\windbg-agent\structscan_x64.dll
```

### 2. Available Commands:

#### 🔹 Mode 1: C/C++ Header Synthesizer (`!structscan emit`)
Synthesizes valid C/C++ struct definitions with accurate alignment, member offsets, type annotations, and symbol-derived field names:
```text
0: kd> !structscan emit nt!KdDebuggerDataBlock 0x400
```

#### 🔹 Mode 2: Bayesian Single-Instance Scan (`!structscan`)
Scans object memory and classifies each 8-byte field using Bayesian inference and heuristic analyzers (pointers, UNICODE_STRING, ASCII strings, PoolTags, Integers, Bitmasks/Flags, Handles, LIST_ENTRY):
```text
0: kd> !structscan nt!PsInitialSystemProcess 0x400
0: kd> !structscan 0xfffff802ac809ab0 0x200
```

#### 🔹 Mode 3: Multi-Instance Cross-Reference (`!structscan list`)
Locates `LIST_ENTRY` links, walks the object chain (up to 64 instances), and cross-evaluates **field type consistency and unique value diversity** across instances:
```text
0: kd> !structscan list nt!PsActiveProcessHead 0x800
```

#### 🔹 Mode 4: Shannon Entropy Heatmap (`!structscan entropy`)
Computes and renders Shannon entropy across 16-byte blocks to pinpoint pointers, encrypted/hashed buffers, tags, and padding regions:
```text
0: kd> !structscan entropy nt!PsInitialSystemProcess 0x200
```

#### 🔹 Mode 5: Control Flow Transfer (CFT) Engine (`!cft`)
Comprehensive execution-flow tracer, PE structure analyzer, and branch correlator for Windows kernel and user-mode targets across **ARM64 (AArch64)** and **x64 (AMD64)** architectures.

**Control-Flow Transfer Categories:**

| Transfer Category | ARM64 Instructions | x64 Instructions | Security & Audit Invariants |
|---|---|---|---|
| **Direct Call** | `bl` | `call rel32` | Callee symbol resolution, module boundaries, import tables |
| **Indirect Call** | `blr`, `blraa`, `blrab` | `call reg`, `call [mem]` | Runtime pointer origin, CFG bitmap validity, PAC key verification |
| **Direct Jump** | `b`, `b.cond`, `cbz`, `tbz` | `jmp rel32`, `jcc` | Intra-procedural edge linking, taken/not-taken branch conditions |
| **Indirect Jump / Return** | `br`, `ret`, `retaa`, `retab` | `jmp reg`, `ret` | Target calculation, return address stack integrity (ROP/JOP check) |

**Subcommands:**
```text
0: kd> !cft pe [module|addr]          <- PE header, sections, CFG & entry point analyzer
0: kd> !cft map [module|addr] [max]   <- Control-flow graph potential edges discovery
0: kd> !cft edge <src> <dst>          <- Inspect a specific control transfer transition
0: kd> !cft trace [sym|addr] [count]  <- ARM / x64 dynamic branch transfer tracer
0: kd> !cft snap                      <- Live snapshot: PC/RIP + regs + disasm + stack + entropy
0: kd> !cft watch <sym|addr>          <- Hardware exec BP + prologue scan + entropy
0: kd> !cft                           <- Automated 6-phase structural analysis
```

---

##### 1. PE Header & Entry Point Analyzer (`!cft pe`)
Parses `IMAGE_DOS_HEADER` (`MZ`) and `IMAGE_NT_HEADERS64` directly from virtual memory:
- Calculates virtual address: `AddressOfEntryPoint (RVA) -> VA`.
- **EntryPoint Hook Detector**: Decodes initial instructions at the entrypoint to detect hooks or trampolines (`b`/`br` on ARM64, `jmp` on x64).
- Security flags: **Control Flow Guard (CFG)**, **High Entropy ASLR**, **NX/DEP**.
- Memory section map with permissions (`R-X`, `RW-`, `R--`) marking executable regions.

**Sample Output (`!cft pe nt`):**
```text
+==============================================================+
|  PE IMAGE & ENTRY POINT ANALYZER (CFT)                       |
+==============================================================+

  Module Name       : nt
  Image Base        : 0x000000009d800000
  Size of Image     : 0x0124a000 (18728 KB)
  Architecture      : ARM64 (AArch64) (0xaa64)
  Number of Sections: 34

  --- Entry Point (Initial Control Transfer) ---
  AddressOfEntryPoint: RVA +0x00a96bc0  ->  VA 0x000000009e296bc0  (nt!KiSystemStartup+0x0)
  Hook Status        : [OK] Normal entry point prologue (unpatched)

  --- Security & Control Flow Integrity ---
  Control Flow Guard (CFG) : ENABLED
  High Entropy ASLR (64-bit): ENABLED
  NX / DEP Compatibility   : ENABLED

  --- Section Table (Memory Regions) ---
  Name      RVA         VirtualSize  RawSize     Flags       Characteristics
  --------  ----------  -----------  ----------  ----------  --------------------------------
  .rdata    +0x00001000  0x0009a0d0   0x0009a200  R--         [DATA / READONLY]
  .pdata    +0x0009c000  0x0003dda8   0x0003de00  R--         [DATA / READONLY]
  .text     +0x00200000  0x0046df04   0x0046e000  R-X         [EXECUTABLE CODE REGION]
  PAGE      +0x0066e000  0x00422ba0   0x00422c00  R-X         [EXECUTABLE CODE REGION]
```

---

##### 2. Control Flow Graph Edge Discovery (`!cft map`)
Scans executable sections of a target PE image to discover and map all potential control-flow edges:
- Identifies direct calls, indirect calls, direct jumps, conditional branches, and returns.
- Categorizes edge scopes:
  - `INTERNAL`: Target is within the same module.
  - `CROSS_MOD`: Inter-modular API transition.
  - `INDIR_DYN`: Runtime-computed destination (requires CFG monitoring).

**Sample Output (`!cft map nt 25`):**
```text
+==============================================================+
|  CONTROL FLOW GRAPH (CFG) POTENTIAL EDGE MAP                 |
+==============================================================+

  Target Module : nt (0x000000009d800000)
  Architecture  : ARM64 (AArch64)
  Max Edges     : 25

  #   Source RVA   Type            Target Address / Target Symbol             Scope
  --  -----------  --------------  -----------------------------------------  -------------
  01  +0x0020001c   CALL            0xfffff8019dc7c840 (nt!_report_gsfailure)  INTERNAL
  03  +0x00200050   CALL            0xfffff8019de2bbf4 (nt!HalpSaveProcessorState)  INTERNAL
  04  +0x00200054   CBNZ            0xfffff8019da00074 (nt!HalpProcessorHaltInternal)  INTERNAL
  09  +0x002000a8   INDIR_JUMP      [reg x1] (runtime computed)                INDIR_DYN
  13  +0x002001a4   INDIR_CALL      [reg x6] (runtime computed)                INDIR_DYN
  22  +0x00200298   RETURN          [reg x30] (runtime computed)               INDIR_DYN

  --- Control-Flow Map Summary ---
  Potential edges mapped: 25
  Internal module edges : 13
  Cross-module API calls: 0
  Indirect/dynamic edges: 11 (require runtime monitoring)
```

---

##### 3. Transition Context Correlator (`!cft edge`)
Performs deep inspection on a specific control-flow edge between `source` and `destination`:
- Verifies module membership of both endpoints.
- Verifies 4-byte instruction alignment on ARM64 (`[!] UNALIGNED DEST`).
- Flags transitions into non-module / dynamic memory (heap/pool execution / shellcode).
- Disassembles 5 instructions leading to the branch and 5 instructions at the destination (including PAC `pacibsp` verification).

**Sample Output (`!cft edge nt!KiSystemService nt!PsInvokeWin32Callout`):**
```text
+==============================================================+
|  TRANSITION CONTEXT INSPECTION & CORRELATOR (CFT)            |
+==============================================================+

  Source Address : 0x000000009de361c0 (nt!KiSystemService+0x0)
  Target Address : 0x000000009e101e80 (nt!PsInvokeWin32Callout+0x0)

  --- Transition Integrity Checks ---
  [OK] Target address is properly aligned.
  [OK] Intra-module transition (within nt).

  --- Source Transition Instructions ---
nt!KiSystemService:
fffff801`9de361c0 d101c3ff sub         sp,sp,#0x70
fffff801`9de361c4 a9057bfd stp         fp,lr,[sp,#0x50]

  --- Target Destination Instructions ---
nt!PsInvokeWin32Callout:
fffff801`9e101e80 d503237f pacibsp
fffff801`9e101e84 a9be53f3 stp         x19,x20,[sp,#-0x20]!
```

---

##### 4. Dynamic Branch Tracer (`!cft trace`)
Analyzes instructions starting at any address or current `PC`/`RIP`:
- **ARM64 Branch Decoder**: decodes `bl`, `blr`, `blraa`, `b`, `br`, `braa`, `b.cond`, `cbz`, `tbnz`, `ret`, `retaa`, `svc`, `eret`.
- **Register Inspection**: queries live register values (`xN`, `lr`) for indirect targets and resolves symbols.
- **Statistical Summary**: counts calls, jumps, conditional branches, returns, and PAC authentications.

**Sample Output (`!cft trace nt!KiSystemService 40`):**
```text
+==============================================================+
|  ARM / x64 CONTROL FLOW TRANSFER TRACER (CFT)                |
+==============================================================+

  Target       : nt!KiSystemService (0x000000009de361c0)
  Instructions : 40
  Architecture : ARM64 (AArch64)

  #   Offset   Address               Type            Instruction & Target
  --  -------  --------------------  --------------  ---------------------------------------------------
  01  +0x0034  0x000000009de361f4  COND_BRANCH     beq  nt!KiSystemService+0x4c -> 0xfffff8019de3620c (nt!KiSystemService+0x4c)
  02  +0x003c  0x000000009de361fc  COND_BRANCH     beq  nt!KiSystemService+0x48 -> 0xfffff8019de36208 (nt!KiSystemService+0x48)
  03  +0x005c  0x000000009de3621c  COND_BRANCH     bhs  nt!KiSystemServiceCopyEnd+0x44 -> 0xfffff8019de3632c (nt!KiSystemServiceCopyEnd+0x44)
  04  +0x0068  0x000000009de36228  CBZ             cbz  x9,nt!KiSystemServiceGdiTebAccess+0x2c -> 0xfffff8019de3625c
  05  +0x0074  0x000000009de36234  CBZ             cbz  x8,nt!KiSystemServiceGdiTebAccess+0x2c -> 0xfffff8019de3625c
  06  +0x0090  0x000000009de36250  CALL            bl   nt!PsInvokeWin32Callout -> 0xfffff8019e101e80 (nt!PsInvokeWin32Callout)

  --- Control Flow Transfer Summary ---
  Instructions scanned : 40
  Control transfers    : 6 (15.0% of code)
  Direct Calls (BL)    : 1
  Indirect Calls (BLR) : 0
  Direct Jumps (B)     : 0
  Indirect Jumps (BR)  : 0
  Cond Branches        : 5
  Returns (RET/PAC)    : 0
  PAC Authenticated    : 0
  Syscalls/Exceptions  : 0
```

---

##### 5. PE Loading Analysis Workflow
To trap and analyze when a new PE image (driver or DLL) is mapped into memory:
1. **Enable module load trap**:
   ```text
   0: kd> sxe ld:mydriver.sys
   0: kd> g
   ```
2. **Capture loader state on break**:
   ```text
   0: kd> !cft snap
   ```
3. **Analyze the newly mapped PE structure**:
   ```text
   0: kd> !cft pe mydriver
   ```
4. **Map potential control-flow edges**:
   ```text
   0: kd> !cft map mydriver 64
   ```
5. **Set execution watchpoint on the EntryPoint**:
   ```text
   0: kd> !cft watch <EntryPoint_VA>
   0: kd> g
   ```

#### 🔹 Mode 6: Use-After-Free Lifetime Analyzer (`!uaf`)
Multi-phase kernel object lifetime analysis designed to detect Use-After-Free conditions, memory reclamation patterns, and dangling pointer references.

**Formal Verification Model:**
```
ALLOC(O) → LIVE(O) → FREE(O) → [REUSE(O)] → USE(O)
                                     ↑
                     Invariant: USE(O) requires LIVE(O)
```

**Syntax:**
```text
!uaf <sym|addr> [objsize] [searchbytes]
```

**Parameters:**
- `sym|addr`    — Target symbol name (e.g. `nt!PsInitialSystemProcess`) or raw virtual address (e.g. `ffff80011234abcd`)
- `objsize`     — Size of target object to analyze in bytes (default: `0x200`)
- `searchbytes` — Kernel VA range centered on the object to scan for dangling back-references (default: `0x8000`)

**Examples:**
```text
0: kd> !uaf nt!PsInitialSystemProcess 0x480
0: kd> !uaf ffff8001`234abcd0 0x300 0x20000
0: kd> !uaf win32k!gpdi
```

**Five Analysis Phases:**

| Phase | Name | Verification Checks |
|---|---|---|
| **1** | Pool Header | PoolType, tag validity, and free-list linkage (`Flink`/`Blink` pointers) |
| **2** | OBJECT_HEADER | `PointerCount` and `HandleCount` destruction heuristics |
| **3** | Content Analysis | Shannon entropy and Bayesian field classification (zeroed runs = red flag) |
| **4** | Dangling References | Reverse pointer scan in kernel address space for active references |
| **5** | Risk Report | Weighted risk score (0–100) + tailored `ba r8` / `ba w8` WinDbg breakpoint recipes |

**Sample Output on UAF Detection:**
```text
================================================================
  StructScan !uaf v4.0  --  Object Lifetime Analyzer
================================================================

  Address  : 0xffff8001234abcd0
  ObjSize  : 0x300 bytes

[=== PHASE 1 · Pool Header Analysis  (object - 0x10) ===]
  PoolTag    : 'Driv' -> DRIVER_OBJECT (Driver)
  PoolType   : 0 (NonPaged/FREE candidate)
  [!] Pool header suggests FREED state:
      - PoolType=0 (classic free indicator)
      - Object[+0]  = 0xffff8001`deadbeef  (free-list Flink?)
      - Object[+8]  = 0xffff8001`cafecafe  (free-list Blink?)

[=== PHASE 4 · Dangling Reference Scan ===]
  [!!] FREED object with 2 dangling pointer(s) -- STRONG UAF SIGNAL

[=== PHASE 5 -- UAF Risk Report ===]

  State   : FREED
  Score   : 90 / 100
  Risk    : [########################################] 90%

  [!!!] HIGH RISK -- LIKELY USE-AFTER-FREE

  WinDbg Breakpoint Recipe:
    ba r8 0xffff8001234abcd0   <- break on any READ of freed object
    ba w8 0xffff8001234abcd0   <- break on re-use/overwrite by allocator

  Formal model at this address:
    t_free < t_use  =>  UAF(O) proven
    Lifetime(O) = [t_alloc, t_free)
    t_use NOT IN Lifetime(O)  =>  USE-AFTER-FREE
```

#### 🔹 Plugin Unload Hint:
```text
0: kd> !structscan unload
[+] Run: .unload structscan
```
---

## 📊 Sample Synthesized C/C++ Header (`!structscan emit`)

```cpp
// Auto-generated by StructScan v4.0 (AI Structure Synthesizer)
// Target: nt!KdDebuggerDataBlock (0x00000000ac600f00) | Scan Window: 0x400 bytes

typedef struct _RECONSTRUCTED_nt_KdDebuggerDataBlock {
    /* +0x0000 */ LIST_ENTRY        Field_0000;              // Flink=0xfffff802ac7ca420 Blink=0xfffff802ac7ca420
    /* +0x0008 */ PVOID             KdpDebuggerDataListHead; // nt!KdpDebuggerDataListHead
    /* +0x0010 */ char              Field_0010[8];           // KDBG
    /* +0x0018 */ PVOID             _guard_eh_cont_table;    // nt!_guard_eh_cont_table <PERF> (nt+0x0)
    /* +0x0020 */ PVOID             DbgBreakPoint;           // nt!DbgBreakPoint
    /* +0x0028 */ uint8_t           Padding_0028[16];
    /* +0x0038 */ PVOID             KiCallUserMode;          // nt!KiCallUserMode
    /* +0x0040 */ uint8_t           Padding_0040[8];
    /* +0x0048 */ PVOID             PsLoadedModuleList;      // nt!PsLoadedModuleList
    /* +0x0050 */ PVOID             PsActiveProcessHead;     // nt!PsActiveProcessHead
    /* +0x0058 */ PVOID             PspCidTable;             // nt!PspCidTable
    /* +0x0060 */ PVOID             ExpSystemResourcesList;  // nt!ExpSystemResourcesList
    /* +0x0068 */ uint8_t           Padding_0068[16];
    /* +0x0078 */ PVOID             KeTimeIncrement;         // nt!KeTimeIncrement
    /* +0x0080 */ PVOID             KeBugCheckCallbackListHead; // nt!KeBugCheckCallbackListHead
    /* +0x0088 */ PVOID             KiBugCheckData;          // nt!KiBugCheckData
    /* +0x0090 */ PVOID             IopErrorLogListHead;     // nt!IopErrorLogListHead
    /* +0x0098 */ PVOID             ObpRootDirectoryObject;  // nt!ObpRootDirectoryObject
    /* +0x00a0 */ PVOID             ObpTypeObjectType;       // nt!ObpTypeObjectType
    /* +0x00a8 */ uint8_t           Padding_00a8[24];
    /* +0x00c0 */ PVOID             MmPfnDatabase;           // nt!MmPfnDatabase
    /* +0x00c8 */ uint8_t           Padding_00c8[112];
    /* +0x0138 */ uint64_t          Field_0138;              // 0x1000 (4096)
    /* +0x0140 */ PVOID             MmSizeOfPagedPoolInBytes; // nt!MmSizeOfPagedPoolInBytes
    /* +0x0148 */ uint8_t           Padding_0148[40];
    /* +0x0170 */ PVOID             MiState;                 // nt!MiState+0xb810
    /* +0x0178 */ uint8_t           Padding_0178[64];
    /* +0x01b8 */ PVOID             PoolTrackTable;          // nt!PoolTrackTable
    /* +0x01c0 */ uint8_t           Padding_01c0[8];
    /* +0x01c8 */ PVOID             MmHighestUserAddress;    // nt!MmHighestUserAddress
    /* +0x01d0 */ PVOID             MmSystemRangeStart;      // nt!MmSystemRangeStart
    /* +0x01d8 */ PVOID             MmUserProbeAddress;      // nt!MmUserProbeAddress
    /* +0x01e0 */ PVOID             KdPrintDefaultCircularBuffer; // nt!KdPrintDefaultCircularBuffer
    /* +0x01e8 */ PVOID             KdPrintRolloverCount;    // nt!KdPrintRolloverCount
    /* +0x01f0 */ PVOID             KdPrintWritePointer;     // nt!KdPrintWritePointer
    /* +0x01f8 */ PVOID             KdPrintRolloverCount;    // nt!KdPrintRolloverCount
    /* +0x0200 */ uint8_t           Padding_0200[8];
    /* +0x0208 */ PVOID             NtBuildLabEx;            // nt!NtBuildLabEx
    /* +0x0210 */ uint8_t           Padding_0210[8];
    /* +0x0218 */ PVOID             KiProcessorBlock;        // nt!KiProcessorBlock
    /* +0x0220 */ PVOID             MmUnloadedDrivers;       // nt!MmUnloadedDrivers
    /* +0x0228 */ PVOID             MmLastUnloadedDriver;    // nt!MmLastUnloadedDriver
    /* +0x0230 */ PVOID             VerifierTriageActionTaken; // nt!VerifierTriageActionTaken
    /* +0x0238 */ PVOID             MmSpecialPoolTag;        // nt!MmSpecialPoolTag
    /* +0x0240 */ PVOID             KernelVerifier;          // nt!KernelVerifier
    /* +0x0248 */ PVOID             MmVerifierData;          // nt!MmVerifierData
    /* +0x0250 */ uint8_t           Padding_0250[24];
    /* +0x0268 */ PVOID             CmNtCSDVersion;          // nt!CmNtCSDVersion
    /* +0x0270 */ PVOID             MmPhysicalMemoryBlock;   // nt!MmPhysicalMemoryBlock
    /* +0x0390 */ PVOID             KePointerAuthMask;       // nt!KePointerAuthMask
} RECONSTRUCTED_nt_KdDebuggerDataBlock, *PRECONSTRUCTED_nt_KdDebuggerDataBlock;
```

---

## 📁 Repository Structure

```text
structscan/
├── include/
│   └── structscan.h          # Core types, classifiers, 55+ NT Pool Tags, entropy, cross-ref APIs
├── src/
│   ├── Main.cpp              # WinDbg extension entry points, command dispatchers, and RAII management
│   ├── Utils.cpp             # Target resolution, symbol queries, and output formatting helpers
│   ├── SmartFieldAnalyzer.cpp# Bayesian field classifier and heuristic analysis engine
│   ├── ScanEngine.cpp        # Single-instance Bayesian scanning engine
│   ├── ListCrossRefEngine.cpp# LIST_ENTRY crawler and multi-instance profile analysis
│   ├── HeaderSynthesizer.cpp # C/C++ header code synthesizer
│   ├── EntropyEngine.cpp     # Shannon entropy heatmap engine
│   ├── UafEngine.cpp         # 5-phase Use-After-Free lifetime analysis engine
│   └── CftEngine.cpp         # Control Flow Transfer (CFT) tracing engine
├── bin/
│   ├── structscan_arm64.dll  # Native ARM64 (AArch64) Windows binary
│   └── structscan_x64.dll    # Native x64 (AMD64) Windows binary
├── build_mingw.sh            # One-click MinGW-w64 cross-compilation script for macOS / Linux
├── CMakeLists.txt            # Multi-platform CMake build configuration
├── _build_arch.bat           # Windows MSVC multi-architecture build driver
└── README.md
```

---

## 🔨 Building from Source

### 🍎 Cross-Compiling on macOS / Linux (via MinGW-w64)

StructScan can be cross-compiled directly on macOS or Linux without needing Visual Studio or Windows:

```bash
# 1. Install MinGW-w64 via Homebrew (macOS)
brew install mingw-w64 cmake

# 2. Build using the provided helper script
./build_mingw.sh

# Or build via CMake
cmake -B build/mingw_x64 -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ -DCMAKE_BUILD_TYPE=Release
cmake --build build/mingw_x64
```

---

### 🪟 Building on Windows (via MSVC & Ninja)

#### Recommended: Multi-Architecture Build Driver (`_build_arch.bat`)
```cmd
:: Build both x64 and ARM64 releases
_build_arch.bat

:: Build x64 only
_build_arch.bat x64

:: Build ARM64 only
_build_arch.bat arm64

:: Clean build directories
_build_arch.bat clean
```

#### Manual MSVC Command-Line:
```cmd
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /std:c++17 /O2 /EHsc /MD /LD /Iinclude ^
    src\Main.cpp src\Utils.cpp src\SmartFieldAnalyzer.cpp ^
    src\ScanEngine.cpp src\ListCrossRefEngine.cpp ^
    src\HeaderSynthesizer.cpp src\EntropyEngine.cpp src\UafEngine.cpp ^
    /link dbgeng.lib dbghelp.lib /OUT:bin\structscan_x64.dll
```

#### Manual CMake with Ninja:
```bash
cmake -S . -B build/x64 -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/x64 -- -j8
```
