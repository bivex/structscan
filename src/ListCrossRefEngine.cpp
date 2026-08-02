/**
 * @file ListCrossRefEngine.cpp
 * @brief Mode 2: Multi-Instance LIST_ENTRY Cross-Reference Engine
 */

#include "../include/structscan.h"

std::vector<ULONG64> CrossRefEngine::WalkListEntry(
    IDebugDataSpaces4* ds,
    ULONG64 headAddr,
    ULONG   listEntryOffsetInStruct,
    ULONG   maxInstances
) {
    std::vector<ULONG64> results;
    if (!ds || headAddr == 0) return results;

    ULONG64 flink = 0;
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(headAddr, &flink, 8, &rd)) || rd != 8) return results;

    ULONG64 current = flink;
    while (current != headAddr && current != 0 &&
           current > 0xFFFF000000000000ULL &&
           results.size() < maxInstances)
    {
        ULONG64 structBase = current - listEntryOffsetInStruct;
        results.push_back(structBase);

        ULONG64 nextFlink = 0;
        if (FAILED(ds->ReadVirtual(current, &nextFlink, 8, &rd)) || rd != 8) break;
        current = nextFlink;
    }
    return results;
}

std::vector<OffsetProfile> CrossRefEngine::AnalyzeListProfiles(
    IDebugDataSpaces4*  ds,
    IDebugSymbols4*     sym,
    const std::vector<ULONG64>& instances,
    ULONG scanWindow
) {
    if (instances.empty() || !ds) return {};

    std::map<ULONG, OffsetProfile> profiles;

    SmartFieldAnalyzer analyzer;
    analyzer.DataSpaces = ds;
    analyzer.Symbols    = sym;

    for (ULONG64 base : instances) {
        std::vector<uint8_t> buf(scanWindow);
        ULONG bytesRead = 0;
        if (FAILED(ds->ReadVirtual(base, buf.data(), scanWindow, &bytesRead)) || bytesRead < 8)
            continue;

        for (ULONG off = 0; off + 8 <= bytesRead; off += 8) {
            auto fa = analyzer.Analyze(buf.data(), bytesRead, off, base);
            auto& prof = profiles[off];
            prof.offset = off;
            prof.observedTypes.push_back(fa.type);
            prof.confidences.push_back(fa.confidence);
            prof.rawValues.push_back(fa.rawValue);
        }
    }

    std::vector<OffsetProfile> result;
    for (auto& [off, prof] : profiles) {
        std::unordered_map<int, int> freq;
        for (auto t : prof.observedTypes) freq[static_cast<int>(t)]++;

        auto domIt = std::max_element(freq.begin(), freq.end(),
            [](auto& a, auto& b) { return a.second < b.second; });

        prof.dominantType    = static_cast<FieldType>(domIt->first);
        prof.typeConsistency = static_cast<double>(domIt->second) / static_cast<double>(prof.observedTypes.size());

        prof.isInteresting = (
            prof.typeConsistency >= 0.6 &&
            prof.dominantType != FieldType::Padding &&
            prof.dominantType != FieldType::Unknown &&
            domIt->second >= 2
        );

        result.push_back(std::move(prof));
    }
    return result;
}

HRESULT DoListCrossRef(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
) {
    ULONG64 headAddr = ResolveTarget(ctrl, sym, target, nullptr, nullptr, 0, nullptr);
    if (headAddr == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] LIST_ENTRY head: 0x%016llx\n",
        static_cast<unsigned long long>(headAddr));

    std::vector<uint8_t> buf0(scanWindow);
    ULONG rd0 = 0;
    if (FAILED(ds->ReadVirtual(headAddr, buf0.data(), scanWindow, &rd0)) || rd0 < 16) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot read head object\n");
        return E_FAIL;
    }

    SmartFieldAnalyzer analyzer;
    analyzer.DataSpaces = ds;
    analyzer.Symbols    = sym;

    struct ListEntryCandidate { ULONG offset; ULONG64 flink; ULONG64 blink; };
    std::vector<ListEntryCandidate> listCandidates;

    for (ULONG off = 0; off + 16 <= rd0; off += 8) {
        uint64_t flink = *reinterpret_cast<const uint64_t*>(buf0.data() + off);
        uint64_t blink = *reinterpret_cast<const uint64_t*>(buf0.data() + off + 8);
        if (flink > 0xFFFF000000000000ULL && blink > 0xFFFF000000000000ULL && flink != blink) {
            uint64_t flinkBlink = 0; ULONG rdx = 0;
            if (SUCCEEDED(ds->ReadVirtual(flink + 8, &flinkBlink, 8, &rdx)) && rdx == 8) {
                if (flinkBlink == (headAddr + off) || flinkBlink == blink) {
                    listCandidates.push_back({ off, flink, blink });
                }
            }
        }
    }

    if (listCandidates.empty()) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[-] No valid LIST_ENTRY found in object. Try !structscan <sym> first to locate list offsets.\n");
        return E_FAIL;
    }

    for (auto& le : listCandidates) {
        wchar_t symBuf[256] = {}; ULONG64 disp = 0;
        std::wstring leAnnot;
        if (SUCCEEDED(sym->GetNameByOffsetWide(le.flink, symBuf, _countof(symBuf), nullptr, &disp)))
            leAnnot = symBuf;

        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Detected LIST_ENTRY at struct+0x%04lx  Flink->%s\n",
            static_cast<unsigned long>(le.offset),
            leAnnot.empty() ? L"<no symbol>" : leAnnot.c_str());
    }

    auto& best = listCandidates[0];
    ULONG64 leHead  = headAddr + best.offset;
    std::vector<ULONG64> instances = CrossRefEngine::WalkListEntry(ds, leHead, best.offset, 64);

    if (instances.empty()) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] List appears empty or head == self\n");
        return S_OK;
    }
    instances.insert(instances.begin(), headAddr);

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Collected %llu struct instances for cross-reference analysis\n\n",
        static_cast<unsigned long long>(instances.size()));

    auto profiles = CrossRefEngine::AnalyzeListProfiles(ds, sym, instances, scanWindow);

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    Type              Consistency  Unique Values  Annotation\n");
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  --------  ----------------  -----------  -------------  --------------------------------\n");

    ULONG reported = 0;
    for (auto& prof : profiles) {
        if (!prof.isInteresting) continue;

        std::vector<uint64_t> sorted = prof.rawValues;
        std::sort(sorted.begin(), sorted.end());
        size_t uniqueVals = std::unique(sorted.begin(), sorted.end()) - sorted.begin();

        std::wstring annotation;
        for (size_t i = 0; i < prof.rawValues.size() && annotation.empty(); i++) {
            uint64_t v = prof.rawValues[i];
            if (v > 0xFFFF000000000000ULL && prof.dominantType == FieldType::Pointer) {
                wchar_t sn[256] = {}; ULONG64 d = 0;
                if (SUCCEEDED(sym->GetNameByOffsetWide(v, sn, _countof(sn), nullptr, &d))) {
                    annotation = sn;
                    if (d) { annotation += L"+..."; }
                    annotation += L" (varies)";
                }
            }
        }
        if (annotation.empty() && prof.dominantType == FieldType::AsciiString) {
            std::wstring vals;
            size_t shown = 0;
            for (size_t i = 0; i < instances.size() && shown < 3; i++) {
                std::vector<uint8_t> b(8);
                ULONG rr = 0;
                if (SUCCEEDED(ds->ReadVirtual(instances[i] + prof.offset, b.data(), 8, &rr))) {
                    std::wstring s;
                    for (auto c : b) if (c >= 0x20 && c <= 0x7E) s += static_cast<wchar_t>(c); else break;
                    if (!s.empty()) { if (!vals.empty()) vals += L"|"; vals += L"\"" + s + L"\""; shown++; }
                }
            }
            annotation = vals;
        }

        wchar_t line[512] = {};
        swprintf_s(line,
            L"  +0x%04lx   %-16s  %3.0f%%         %llu/%llu          %s\n",
            static_cast<unsigned long>(prof.offset),
            FieldTypeName(prof.dominantType),
            prof.typeConsistency * 100.0,
            static_cast<unsigned long long>(uniqueVals),
            static_cast<unsigned long long>(prof.rawValues.size()),
            annotation.c_str()
        );
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"%s", line);
        reported++;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Cross-reference complete: %lu consistent fields identified across %llu instances\n",
        static_cast<unsigned long>(reported),
        static_cast<unsigned long long>(instances.size()));
    return S_OK;
}
