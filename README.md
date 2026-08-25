# StructScan WinDbg Extension (v4.0)

**StructScan** is a high-performance extension plugin for the WinDbg debugger (`dbgeng.dll`), designed for **automated reconstruction of undocumented data structures** (such as opaque kernel structures lacking private PDB symbols, custom driver objects, `ntdsai!gAnchor`, `nt!_OBJECT_TYPE`, etc.) and instant synthesis of ready-to-use C/C++ header definitions.

Version **v4.0** features high-speed virtual memory analysis (`ReadVirtual`), automated C/C++ header synthesis (`emit`), Shannon entropy profiling (`entropy`), Bayesian field classification, multi-instance cross-referencing via `LIST_ENTRY` chains (`list`), and advanced kernel-level Use-After-Free lifetime analysis (`!uaf`).

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

#### 🔹 Mode 5: Use-After-Free Lifetime Analyzer (`!uaf`)
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
│   └── UafEngine.cpp         # 5-phase Use-After-Free lifetime analysis engine
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
