/**
 * @file SmartFieldAnalyzer.cpp
 * @brief Core Bayesian Field Classification Engine
 */

#include "../include/structscan.h"
#include <cwchar>

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

    if (offset + 8 > bufSize) return result;

    const uint8_t* ptr = buf + offset;
    result.rawValue = *reinterpret_cast<const uint64_t*>(ptr);
    result.entropy  = ComputeEntropy(ptr, 8);

    bool f_allZero      = (result.rawValue == 0);
    bool f_kernelPtr    = (result.rawValue > 0xFFFF000000000000ULL);
    bool f_lowEntropy   = (result.entropy  < 1.0);
    bool f_highEntropy  = (result.entropy  > 6.5);
    bool f_smallInt     = (result.rawValue < 0x10000ULL && result.rawValue > 0);
    bool f_aligned      = ((result.rawValue & 0x7) == 0);
    bool f_sparsePopcount = false;
    bool f_validPoolTag = false;
    bool f_resolvesSym  = false;
    bool f_isListEntry  = false;
    bool f_isUnicodeStr = false;
    bool f_isAscii      = false;
    ULONG asciiLen      = 0;

    {
        int pop = PopCount(result.rawValue);
        f_sparsePopcount = (pop >= 1 && pop <= 12 && !f_smallInt);
    }

    {
        uint32_t tagVal = static_cast<uint32_t>(result.rawValue & 0xFFFFFFFF);
        f_validPoolTag  = IsValidPoolTag(tagVal);
    }

    wchar_t symName[256] = {};
    ULONG64 displacement = 0;
    if (f_kernelPtr && Symbols) {
        if (SUCCEEDED(Symbols->GetNameByOffsetWide(result.rawValue, symName, _countof(symName), nullptr, &displacement))) {
            f_resolvesSym = true;
            result.annotation = symName;
            result.ptrTarget  = result.rawValue;
            if (displacement > 0) {
                result.annotation += L"+0x";
                wchar_t dispBuf[32] = {};
                swprintf_s(dispBuf, L"%llx", displacement);
                result.annotation += dispBuf;
            }
        }
    }

    if (f_kernelPtr && DataSpaces && offset + 16 <= bufSize) {
        uint64_t flinkVal  = result.rawValue;
        uint64_t blinkVal  = *reinterpret_cast<const uint64_t*>(ptr + 8);
        if (flinkVal > 0xFFFF000000000000ULL && blinkVal > 0xFFFF000000000000ULL) {
            uint64_t flinkBlink = 0;
            ULONG rd = 0;
            if (SUCCEEDED(DataSpaces->ReadVirtual(flinkVal + 8, &flinkBlink, sizeof(uint64_t), &rd)) && rd == 8) {
                if (flinkBlink == result.address || flinkBlink == blinkVal) {
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

    if (offset + 16 <= bufSize) {
        uint16_t uLen    = *reinterpret_cast<const uint16_t*>(ptr);
        uint16_t uMaxLen = *reinterpret_cast<const uint16_t*>(ptr + 2);
        uint64_t uBuf    = *reinterpret_cast<const uint64_t*>(ptr + 8);
        if (uLen > 0 && uLen <= uMaxLen && uMaxLen <= 1024 &&
            (uLen % 2) == 0 && uBuf > 0xFFFF000000000000ULL && DataSpaces)
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

    struct TypeScore { FieldType type; double score; };
    std::array<TypeScore, 9> scores = {{
        { FieldType::Padding,       0.0 },
        { FieldType::ListEntry,     0.0 },
        { FieldType::UnicodeString, 0.0 },
        { FieldType::Pointer,       0.0 },
        { FieldType::AsciiString,   0.0 },
        { FieldType::PoolTag,       0.0 },
        { FieldType::Handle,        0.0 },
        { FieldType::Flags,         0.0 },
        { FieldType::Integer,       0.0 },
    }};

    auto& [t_Pad, t_List, t_Uni, t_Ptr, t_Asc, t_Tag, t_Hnd, t_Flg, t_Int] = scores;

    if (f_allZero)          { t_Pad.score  += 4.0; t_Int.score  -= 2.0; t_Ptr.score -= 3.0; }
    if (f_lowEntropy)       { t_Pad.score  += 2.0; t_Asc.score  -= 1.0; }
    if (f_isListEntry)      { t_List.score += 8.0; t_Ptr.score  -= 2.0; }
    if (f_isUnicodeStr)     { t_Uni.score  += 8.0; t_Asc.score  -= 3.0; }
    if (f_kernelPtr)        { t_Ptr.score  += 4.0; t_Int.score  -= 3.0; t_Tag.score -= 3.0; }
    if (f_resolvesSym)      { t_Ptr.score  += 4.0; }
    if (f_highEntropy && f_kernelPtr) { t_Ptr.score += 1.0; }
    if (f_isAscii)          { t_Asc.score  += 3.0 + (asciiLen > 8 ? 2.0 : 0.0); }
    if (f_isAscii && !f_kernelPtr) { t_Asc.score += 2.0; }
    if (f_validPoolTag && !f_kernelPtr && !f_smallInt) { t_Tag.score += 4.0; }
    if (f_aligned && f_smallInt) { t_Hnd.score += 1.5; }
    if ((result.rawValue & 0xFFFFFFFF00000000ULL) == 0xFFFFFFFF00000000ULL) { t_Hnd.score += 2.0; }
    if (f_sparsePopcount && !f_kernelPtr && !f_smallInt) { t_Flg.score += 2.0; }
    if (f_smallInt)         { t_Int.score  += 3.0; t_Flg.score  -= 1.0; }
    if (!f_kernelPtr && !f_isAscii && !f_isUnicodeStr && !f_validPoolTag && !f_isListEntry)
                            { t_Int.score  += 0.5; }

    auto winner = std::max_element(scores.begin(), scores.end(),
        [](const TypeScore& a, const TypeScore& b) { return a.score < b.score; });

    double posSum = 0.0;
    for (auto& s : scores) if (s.score > 0) posSum += s.score;
    result.type       = (winner->score > 0.0) ? winner->type : FieldType::Unknown;
    { double c = (posSum > 0) ? (winner->score / posSum) : 0.0; result.confidence = c < 1.0 ? c : 1.0; }

    if (result.annotation.empty()) {
        wchar_t buf[128] = {};
        switch (result.type) {
            case FieldType::PoolTag: {
                uint32_t tagVal = static_cast<uint32_t>(result.rawValue & 0xFFFFFFFF);
                auto* known = FindPoolTag(tagVal);
                if (known) {
                    swprintf_s(buf, L"'%c%c%c%c' (%S)",
                        (tagVal) & 0xFF, (tagVal >> 8) & 0xFF,
                        (tagVal >> 16) & 0xFF, (tagVal >> 24) & 0xFF,
                        known->description);
                } else {
                    swprintf_s(buf, L"'%c%c%c%c'",
                        (tagVal) & 0xFF, (tagVal >> 8) & 0xFF,
                        (tagVal >> 16) & 0xFF, (tagVal >> 24) & 0xFF);
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
