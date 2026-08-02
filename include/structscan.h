/**
 * @file structscan.h
 * @brief StructScan v4.0 — Modular Architecture Header & Engine Interfaces
 * @author Joseph Ryan Ries (2022) / Modernized & AI-Enhanced by Antigravity AI (2026)
 */

#ifndef STRUCTSCAN_H
#define STRUCTSCAN_H

#define NOMINMAX   // Prevent Windows.h from defining min/max macros
#define INITGUID
#include <windows.h>
#include <dbgeng.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <array>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <map>
#include <unordered_map>
#include <optional>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags);
__declspec(dllexport) void CALLBACK DebugExtensionUninitialize(void);
__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args);

#ifdef __cplusplus
}
#endif

constexpr uint32_t MAKE_TAG(char a, char b, char c, char d) {
    return static_cast<uint32_t>(static_cast<uint8_t>(a))        |
          (static_cast<uint32_t>(static_cast<uint8_t>(b)) << 8)  |
          (static_cast<uint32_t>(static_cast<uint8_t>(c)) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>(d)) << 24);
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Type Classification System
// ─────────────────────────────────────────────────────────────────────────────

enum class FieldType : uint8_t {
    Unknown       = 0,
    Pointer       = 1,
    ListEntry     = 2,
    UnicodeString = 3,
    AsciiString   = 4,
    PoolTag       = 5,
    Integer       = 6,
    Flags         = 7,
    Handle        = 8,
    Padding       = 9,
};

static const wchar_t* FieldTypeName(FieldType t) {
    switch (t) {
        case FieldType::Pointer:       return L"Pointer";
        case FieldType::ListEntry:     return L"LIST_ENTRY";
        case FieldType::UnicodeString: return L"UNICODE_STRING";
        case FieldType::AsciiString:   return L"ASCII";
        case FieldType::PoolTag:       return L"PoolTag";
        case FieldType::Integer:       return L"Integer";
        case FieldType::Flags:         return L"Flags";
        case FieldType::Handle:        return L"Handle";
        case FieldType::Padding:       return L"Padding";
        default:                       return L"Unknown";
    }
}

struct FieldAnalysis {
    ULONG        offset;
    ULONG64      address;
    uint64_t     rawValue;
    FieldType    type;
    double       confidence;
    double       entropy;
    std::wstring annotation;
    ULONG64      ptrTarget;
    bool         isListEntry;
    ULONG        size;
};

struct OffsetProfile {
    ULONG                  offset;
    std::vector<FieldType> observedTypes;
    std::vector<double>    confidences;
    std::vector<uint64_t>  rawValues;
    FieldType              dominantType;
    double                 typeConsistency;
    bool                   isInteresting;
};

struct PoolTagInfo {
    uint32_t    tag;
    const char* description;
    ULONG       estimatedSize;
};

static constexpr PoolTagInfo kKnownPoolTags[] = {
    { MAKE_TAG('P','r','o','c'), "EPROCESS (Process)",         0xB80 },
    { MAKE_TAG('T','h','r','e'), "ETHREAD (Thread)",           0x5C0 },
    { MAKE_TAG('F','i','l','e'), "FILE_OBJECT (File)",         0x120 },
    { MAKE_TAG('D','r','i','v'), "DRIVER_OBJECT (Driver)",     0x150 },
    { MAKE_TAG('D','e','v','i'), "DEVICE_OBJECT (Device)",     0x200 },
    { MAKE_TAG('T','o','k','e'), "TOKEN (Security Token)",    0x300 },
    { MAKE_TAG('P','o','r','t'), "ALPC_PORT (LPC/ALPC Port)", 0x180 },
    { MAKE_TAG('J','o','b',' '), "JOB (Job Object)",          0x280 },
    { MAKE_TAG('E','v','n','t'), "KEVENT (Kernel Event)",     0x18  },
    { MAKE_TAG('M','u','t','x'), "KMUTANT (Mutex)",           0x38  },
    { MAKE_TAG('S','e','m',' '), "KSEMAPHORE (Semaphore)",    0x20  },
    { MAKE_TAG('T','i','m','r'), "KTIMER (Timer)",            0x40  },
    { MAKE_TAG('S','e','c','t'), "SECTION (Memory Section)", 0x90  },
    { MAKE_TAG('S','y','m','b'), "OBJECT_SYMBOLIC_LINK",     0x48  },
    { MAKE_TAG('D','i','r',' '), "OBJECT_DIRECTORY (Folder)", 0x200 },
    { MAKE_TAG('K','e','y',' '), "CMKEY_BODY (Registry Key)",  0x68  },
    { MAKE_TAG(' ','I','n','T'), "IRP (I/O Request Packet)",   0x118 },
    { MAKE_TAG('I','o',' ',' '), "IO_STATUS_BLOCK",            0x10  },
    { MAKE_TAG('N','F','s',' '), "NTFS Control Block",         0x100 },
    { MAKE_TAG('F','L','t',' '), "Filter Manager Callback",    0x40  },
    { MAKE_TAG('F','l','y',' '), "Filter Manager Data",        0x80  },
    { MAKE_TAG('P','o','o','l'), "Pool Descriptor",            0     },
    { MAKE_TAG('N','t','V','m'), "NtVm Region",                0     },
    { MAKE_TAG('H','e','a','p'), "Heap Allocation",            0     },
    { MAKE_TAG('M','m','M','l'), "MDL (Memory Descriptor)",    0x30  },
    { MAKE_TAG('M','m','L','k'), "Mm Locked Pages",            0     },
    { MAKE_TAG('M','m','V','w'), "Mm View (MMVIEW)",           0     },
    { MAKE_TAG('S','W','a','p'), "Paging File / Swap",         0     },
    { MAKE_TAG('P','t','e',' '), "PTE (Page Table Entry)",     0x8   },
    { MAKE_TAG('A','c','l',' '), "ACL (Access Control List)",  0     },
    { MAKE_TAG('S','e','c','u'), "SECURITY_DESCRIPTOR",        0     },
    { MAKE_TAG('S','y','s','m'), "System Memory Allocation",   0     },
    { MAKE_TAG('k','W','x',' '), "WORK_QUEUE_ITEM",            0x20  },
    { MAKE_TAG('C','D','S',' '), "Code Integrity / CI",        0     },
    { MAKE_TAG('A','m','D','g'), "DMA Adapter",                0     },
    { MAKE_TAG('D','N','d',' '), "NDIS Driver Block",          0x200 },
    { MAKE_TAG('N','T','k',' '), "NetBT Network Buffer",       0     },
    { MAKE_TAG('C','T','c',' '), "TCP Connection Block (TCB)", 0x300 },
    { MAKE_TAG('U','T','p',' '), "UDP Endpoint Block",         0x100 },
    { MAKE_TAG('I','F','s',' '), "RDBSS / IFS Mini-Redirector",0     },
    { MAKE_TAG('E','M','e','t'), "ETW_GUID_ENTRY",             0x50  },
    { MAKE_TAG('E','C','t',' '), "ETW Trace Session",          0x100 },
    { MAKE_TAG('E','T','p',' '), "ETW Provider Object",        0x80  },
    { MAKE_TAG('E','C','r',' '), "ETW Realtime Consumer",      0x80  },
    { MAKE_TAG('W','K','b',' '), "WMI Buffer",                 0x1000},
    { MAKE_TAG('W','K','g',' '), "WMI GUID Object",            0x60  },
    { MAKE_TAG('W','C','l',' '), "WPP Trace Log",              0     },
    { MAKE_TAG('P','K','a',' '), "PnP Auto-Play / Arrival",    0     },
    { MAKE_TAG('P','K','d',' '), "DEVICE_NODE (PnP DevNode)",  0x1c0 },
    { MAKE_TAG('P','K','r',' '), "PnP Relation List",          0     },
    { MAKE_TAG('P','V','d',' '), "Power Manager State",        0     },
    { MAKE_TAG('P','R','i',' '), "Power Request Object",       0x80  },
    { MAKE_TAG('W','v','h',' '), "Hyper-V Hypervisor Call",    0     },
    { MAKE_TAG('H','V','s',' '), "Hyper-V Synthetic Device",   0     },
    { MAKE_TAG('H','S','m',' '), "Hyper-V Shared Memory",      0     },
    { MAKE_TAG('H','V','r',' '), "Hyper-V Root Partition",     0     },
};

class SmartFieldAnalyzer {
public:
    IDebugDataSpaces4* DataSpaces{nullptr};
    IDebugSymbols4*    Symbols{nullptr};

    static double ComputeEntropy(const uint8_t* data, size_t len) {
        if (len == 0) return 0.0;
        uint32_t freq[256] = {};
        for (size_t i = 0; i < len; i++) freq[data[i]]++;
        double H = 0.0;
        for (auto f : freq) {
            if (f) {
                double p = static_cast<double>(f) / static_cast<double>(len);
                H -= p * log2(p);
            }
        }
        return H;
    }

    static int PopCount(uint64_t v) {
        int count = 0;
        while (v) { count += (v & 1); v >>= 1; }
        return count;
    }

    static const PoolTagInfo* FindPoolTag(uint32_t tagVal) {
        for (auto& pt : kKnownPoolTags) {
            if (pt.tag == tagVal) return &pt;
        }
        return nullptr;
    }

    static bool IsValidPoolTag(uint32_t tagVal) {
        for (int i = 0; i < 4; i++) {
            uint8_t b = (tagVal >> (i * 8)) & 0xFF;
            if (b < 0x20 || b > 0x7E) return false;
        }
        return true;
    }

    FieldAnalysis Analyze(
        const uint8_t* buf, size_t bufSize,
        ULONG offset,
        ULONG64 baseAddr
    );
};

class CrossRefEngine {
public:
    static std::vector<ULONG64> WalkListEntry(
        IDebugDataSpaces4* ds,
        ULONG64 headAddr,
        ULONG   listEntryOffsetInStruct,
        ULONG   maxInstances = 64
    );

    static std::vector<OffsetProfile> AnalyzeListProfiles(
        IDebugDataSpaces4*  ds,
        IDebugSymbols4*     sym,
        const std::vector<ULONG64>& instances,
        ULONG scanWindow
    );
};

class OutputCaptureCallback : public IDebugOutputCallbacks2 {
private:
    ULONG m_refCount{1};
    std::wstring m_capturedOutput;
    IDebugClient* m_client{nullptr};
    PDEBUG_OUTPUT_CALLBACKS m_prevCallback{nullptr};

public:
    OutputCaptureCallback() = default;

    HRESULT Initialize(IDebugClient* client) {
        m_client = client;
        if (!m_client) return E_INVALIDARG;
        HRESULT hr = m_client->GetOutputCallbacks(&m_prevCallback);
        if (FAILED(hr)) m_prevCallback = nullptr;
        return m_client->SetOutputCallbacks(reinterpret_cast<PDEBUG_OUTPUT_CALLBACKS>(this));
    }

    void Restore() {
        if (m_client) m_client->SetOutputCallbacks(m_prevCallback);
    }

    ~OutputCaptureCallback() { Restore(); }

    void Clear() { m_capturedOutput.clear(); }
    const std::wstring& GetOutput() const { return m_capturedOutput; }

    STDMETHODIMP QueryInterface(REFIID InterfaceId, PVOID* Interface) override {
        if (InterfaceId == __uuidof(IUnknown) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks2)) {
            *Interface = static_cast<IDebugOutputCallbacks2*>(this);
            AddRef(); return S_OK;
        }
        *Interface = nullptr; return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return ++m_refCount; }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }
    STDMETHODIMP Output(ULONG, PCSTR Text) override {
        if (Text) {
            int n = MultiByteToWideChar(CP_ACP, 0, Text, -1, nullptr, 0);
            if (n > 0) {
                std::vector<wchar_t> wb(n);
                MultiByteToWideChar(CP_ACP, 0, Text, -1, wb.data(), n);
                m_capturedOutput += wb.data();
            }
        }
        return S_OK;
    }
    STDMETHODIMP GetInterestMask(PULONG Mask) override {
        if (Mask) *Mask = DEBUG_OUTCBI_ANY_FORMAT;
        return S_OK;
    }
    STDMETHODIMP Output2(ULONG, ULONG, ULONG64, PCWSTR Text) override {
        if (Text) m_capturedOutput += Text;
        return S_OK;
    }
};

ULONG64 ResolveTarget(
    IDebugControl4*  ctrl,
    IDebugSymbols4*  sym,
    const wchar_t*   token,
    ULONG64*         outModBase = nullptr,
    wchar_t*         outModName = nullptr,
    size_t           modNameCch = 0,
    ULONG*           outModSize = nullptr
);

std::wstring ConfBar(double conf, int width = 8);
void PrintField(IDebugControl4* ctrl, const FieldAnalysis& fa);

HRESULT DoSingleScan(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
);

HRESULT DoListCrossRef(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
);

HRESULT DoEmitHeader(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
);

HRESULT DoEntropyMap(
    IDebugControl4*    ctrl,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    IDebugSymbols4*    sym,
    ULONG              scanWindow
);

#endif // STRUCTSCAN_H
