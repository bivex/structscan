/**
 * @file SmartFieldAnalyzer.cpp
 * @brief Core Bayesian Field Classification Engine
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cmath>
#include <map>
#include <algorithm>

// PAC stripping for ARM64 kernel pointers
static uint64_t StripPAC(uint64_t val) {
    // If bits 55-63 are modified by PAC, we sign-extend bit 54.
    // Standard ARM64 kernel VA has bit 55 set to 1.
    // A simple heuristic for kernel pointers:
    if ((val & 0x0080000000000000ULL) != 0) {
        return val | 0xFFFF000000000000ULL;
    }
    return val;
}

FieldAnalysis SmartFieldAnalyzer::Analyze(
    const uint8_t* buf, size_t bufSize,
    ULONG offset,
    ULONG64 baseAddr
) {
    FieldAnalysis result{};
    result.offset  = offset;
    result.address = baseAddr + offset;
    result.type    = FieldType::Unknown;
    result.confidence = 0.0;
    result.size = 8; // Default size

    if (offset + 8 > bufSize) {
        result.size = bufSize - offset;
        return result;
    }

    const uint8_t* ptr = buf + offset;
    uint64_t raw64 = *reinterpret_cast<const uint64_t*>(ptr);
    uint32_t raw32 = *reinterpret_cast<const uint32_t*>(ptr);
    
    result.rawValue = raw64;
    result.entropy  = ComputeEntropy(ptr, 8);
    
    uint64_t strippedPtr = StripPAC(raw64);

    bool f_allZero      = (raw64 == 0);
    bool f_kernelPtr    = (strippedPtr >= 0xFFFF000000000000ULL && strippedPtr < 0xFFFFFFFFFFFFFFFFULL);
    bool f_lowEntropy   = (result.entropy  < 0.6);
    bool f_highEntropy  = (result.entropy  > 2.5); // Max possible entropy for 8 bytes is log2(8) = 3.0 bits
    bool f_smallInt     = (raw64 < 0x10000ULL && raw64 > 0);
    bool f_aligned      = ((raw64 & 0x7) == 0);
    bool f_sparsePopcount = false;
    bool f_validPoolTag = false;
    bool f_resolvesSym  = false;
    bool f_isListEntry  = false;
    bool f_isUnicodeStr = false;
    bool f_isAscii      = false;
    ULONG asciiLen      = 0;

    {
        int pop = PopCount(raw64);
        f_sparsePopcount = (pop >= 1 && pop <= 12 && !f_smallInt);
    }

    {
        f_validPoolTag  = IsValidPoolTag(raw32);
    }

    wchar_t symName[256] = {};
    ULONG64 displacement = 0;
    if (f_kernelPtr && Symbols) {
        if (SUCCEEDED(Symbols->GetNameByOffsetWide(strippedPtr, symName, _countof(symName), nullptr, &displacement))) {
            f_resolvesSym = true;
            result.annotation = symName;
            result.ptrTarget  = strippedPtr;
            if (displacement > 0) {
                result.annotation += L"+0x";
                wchar_t dispBuf[32] = {};
                swprintf_s(dispBuf, L"%llx", displacement);
                result.annotation += dispBuf;
            }
        }
    }

    // LIST_ENTRY detection (Context-aware, 16 bytes)
    if (f_kernelPtr && DataSpaces && offset + 16 <= bufSize) {
        uint64_t flinkVal  = strippedPtr;
        uint64_t blinkVal  = StripPAC(*reinterpret_cast<const uint64_t*>(ptr + 8));
        if (flinkVal >= 0xFFFF000000000000ULL && blinkVal >= 0xFFFF000000000000ULL) {
            uint64_t flinkBlink = 0;
            ULONG rd = 0;
            if (SUCCEEDED(DataSpaces->ReadVirtual(flinkVal + 8, &flinkBlink, sizeof(uint64_t), &rd)) && rd == 8) {
                flinkBlink = StripPAC(flinkBlink);
                if (flinkBlink == result.address || (flinkVal == blinkVal && flinkBlink == flinkVal)) {
                    f_isListEntry = true;
                    result.isListEntry = true;
                    wchar_t leBuf[128] = {};
                    swprintf_s(leBuf, L"Flink=0x%llx Blink=0x%llx",
                        static_cast<unsigned long long>(flinkVal),
                        static_cast<unsigned long long>(blinkVal));
                    result.annotation = leBuf;
                }
            }
        }
    }

    // UNICODE_STRING detection (Context-aware, 16 bytes)
    if (offset + 16 <= bufSize) {
        uint16_t uLen    = *reinterpret_cast<const uint16_t*>(ptr);
        uint16_t uMaxLen = *reinterpret_cast<const uint16_t*>(ptr + 2);
        uint64_t uBuf    = StripPAC(*reinterpret_cast<const uint64_t*>(ptr + 8));
        if (uLen > 0 && uLen <= uMaxLen && uMaxLen <= 1024 &&
            (uLen % 2) == 0 && uBuf >= 0xFFFF000000000000ULL && DataSpaces)
        {
            std::vector<wchar_t> wstr(uLen / 2 + 1, 0);
            ULONG uRead = 0;
            if (SUCCEEDED(DataSpaces->ReadVirtual(uBuf, wstr.data(), uLen, &uRead)) && uRead > 0) {
                bool valid = true;
                for (size_t i = 0; i < uLen / 2 && i < 64; i++) {
                    wchar_t wc = wstr[i];
                    if (wc != 0 && (wc < 0x0020 || wc > 0xD7FF) && (wc < 0xE000 || wc > 0xFFFD)) {
                        valid = false; break;
                    }
                }
                if (valid) {
                    f_isUnicodeStr = true;
                    result.annotation = std::wstring(wstr.data(), uLen / 2);
                }
            }
        }
    }

    {
        size_t run = 0;
        while (offset + run < bufSize && ptr[run] >= 0x20 && ptr[run] <= 0x7E) run++;
        if (run >= 4) {
            f_isAscii = true;
            asciiLen  = static_cast<ULONG>(run);
        }
    }

    // Naive Bayes Probabilities P(Feature | Class)
    // Classes: Padding, ListEntry, UnicodeString, Pointer, AsciiString, PoolTag, Handle, Flags, Integer
    struct BayesClass {
        FieldType type;
        double prior;
        double p_allZero, p_kernelPtr, p_lowEntropy, p_highEntropy, p_smallInt;
        double p_sparsePop, p_validPoolTag, p_resolvesSym, p_isListEntry, p_isUnicodeStr, p_isAscii;
        ULONG expectedSize;
    };

    BayesClass classes[] = {
        { FieldType::Padding,       0.20, 0.95, 0.01, 0.90, 0.01, 0.05, 0.01, 0.01, 0.001, 0.001, 0.001, 0.01, 8 },
        { FieldType::ListEntry,     0.05, 0.001, 0.99, 0.10, 0.80, 0.001, 0.10, 0.001, 0.80, 0.99, 0.001, 0.01, 16},
        { FieldType::UnicodeString, 0.05, 0.001, 0.05, 0.10, 0.50, 0.10, 0.10, 0.01, 0.01, 0.001, 0.99, 0.01, 16},
        { FieldType::Pointer,       0.30, 0.001, 0.99, 0.10, 0.80, 0.001, 0.10, 0.01, 0.80, 0.001, 0.001, 0.01, 8 },
        { FieldType::AsciiString,   0.05, 0.001, 0.01, 0.10, 0.50, 0.01, 0.10, 0.01, 0.001, 0.001, 0.001, 0.99, 8 },
        { FieldType::PoolTag,       0.05, 0.001, 0.01, 0.10, 0.50, 0.01, 0.10, 0.99, 0.001, 0.001, 0.001, 0.95, 4 },
        { FieldType::Handle,        0.05, 0.001, 0.01, 0.80, 0.01, 0.60, 0.10, 0.01, 0.001, 0.001, 0.001, 0.01, 8 },
        { FieldType::Flags,         0.10, 0.05, 0.01, 0.80, 0.10, 0.20, 0.90, 0.01, 0.001, 0.001, 0.001, 0.01, 4 },
        { FieldType::Integer,       0.15, 0.01, 0.01, 0.50, 0.50, 0.50, 0.50, 0.01, 0.001, 0.001, 0.001, 0.01, 4 },
    };

    double maxPosterior = -1.0;
    FieldType bestType = FieldType::Unknown;
    ULONG bestSize = 8;
    double evidence = 0.0;
    
    std::vector<double> posteriors(9, 0.0);

    for (size_t i = 0; i < 9; i++) {
        auto& c = classes[i];
        double p = c.prior;
        p *= f_allZero ? c.p_allZero : (1.0 - c.p_allZero);
        p *= f_kernelPtr ? c.p_kernelPtr : (1.0 - c.p_kernelPtr);
        p *= f_lowEntropy ? c.p_lowEntropy : (1.0 - c.p_lowEntropy);
        p *= f_highEntropy ? c.p_highEntropy : (1.0 - c.p_highEntropy);
        p *= f_smallInt ? c.p_smallInt : (1.0 - c.p_smallInt);
        p *= f_sparsePopcount ? c.p_sparsePop : (1.0 - c.p_sparsePop);
        p *= f_validPoolTag ? c.p_validPoolTag : (1.0 - c.p_validPoolTag);
        p *= f_resolvesSym ? c.p_resolvesSym : (1.0 - c.p_resolvesSym);
        p *= f_isListEntry ? c.p_isListEntry : (1.0 - c.p_isListEntry);
        p *= f_isUnicodeStr ? c.p_isUnicodeStr : (1.0 - c.p_isUnicodeStr);
        p *= f_isAscii ? c.p_isAscii : (1.0 - c.p_isAscii);
        
        posteriors[i] = p;
        evidence += p;
    }

    for (size_t i = 0; i < 9; i++) {
        if (evidence > 0) posteriors[i] /= evidence;
        if (posteriors[i] > maxPosterior) {
            maxPosterior = posteriors[i];
            bestType = classes[i].type;
            bestSize = classes[i].expectedSize;
        }
    }

    result.type = bestType;
    result.confidence = maxPosterior;
    result.size = bestSize;

    if (f_isAscii && bestType == FieldType::AsciiString) {
        result.size = (asciiLen + 7) & ~7; // align to 8
    }

    if (result.annotation.empty()) {
        wchar_t buf[128] = {};
        switch (result.type) {
            case FieldType::PoolTag: {
                auto* known = FindPoolTag(raw32);
                if (known) {
                    swprintf_s(buf, L"'%c%c%c%c' (%S)",
                        (raw32) & 0xFF, (raw32 >> 8) & 0xFF,
                        (raw32 >> 16) & 0xFF, (raw32 >> 24) & 0xFF,
                        known->description);
                } else {
                    swprintf_s(buf, L"'%c%c%c%c'",
                        (raw32) & 0xFF, (raw32 >> 8) & 0xFF,
                        (raw32 >> 16) & 0xFF, (raw32 >> 24) & 0xFF);
                }
                result.annotation = buf;
                break;
            }
            case FieldType::AsciiString: {
                std::wstring ws;
                ULONG asciiCap = asciiLen < 64u ? asciiLen : 64u;
                for (ULONG i = 0; i < asciiCap; i++)
                    ws += static_cast<wchar_t>(ptr[i]);
                result.annotation = ws;
                break;
            }
            case FieldType::Integer:
                swprintf_s(buf, L"0x%llx (%llu)", result.rawValue, result.rawValue);
                result.annotation = buf;
                break;
            case FieldType::Flags:
                swprintf_s(buf, L"0x%llx (popcount=%d)", result.rawValue, PopCount(result.rawValue));
                result.annotation = buf;
                break;
            case FieldType::Handle:
                swprintf_s(buf, L"0x%llx", result.rawValue);
                result.annotation = buf;
                break;
            default: break;
        }
    }

    return result;
}
