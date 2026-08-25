/**
 * @file ListCrossRefEngine.cpp
 * @brief Mode 2: Multi-Instance LIST_ENTRY Cross-Reference Engine
 */

#include "../include/structscan.h"

#include <unordered_set>

std::vector<ULONG64> CrossRefEngine::WalkListEntry(
    IDebugDataSpaces4* ds,
    ULONG64 headAddr,
    ULONG   listEntryOffsetInStruct,
    ULONG   maxInstances
) {
    std::vector<ULONG64> results;
    if (!ds || headAddr == 0) return results;

    std::unordered_set<ULONG64> visited;
    visited.insert(headAddr);

    ULONG64 flink = 0;
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(headAddr, &flink, 8, &rd)) || rd != 8) return results;

    ULONG64 current = flink;
    while (current != headAddr && current != 0 &&
           current > 0xFFFF000000000000ULL &&
           results.size() < maxInstances)
    {
        if (visited.count(current)) break; // Cycle / loop detected
        visited.insert(current);

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

struct ListEntryCandidate {
    ULONG   offset;
    ULONG64 flink;
    ULONG64 blink;
};

static std::vector<ListEntryCandidate> FindListCandidates(
    IDebugDataSpaces4* ds,
    const uint8_t* buf,
    ULONG rd,
    ULONG64 headAddr
) {
    std::vector<ListEntryCandidate> listCandidates;
    for (ULONG off = 0; off + 16 <= rd; off += 8) {
        uint64_t flink = *reinterpret_cast<const uint64_t*>(buf + off);
        uint64_t blink = *reinterpret_cast<const uint64_t*>(buf + off + 8);
        if (flink > 0xFFFF000000000000ULL && blink > 0xFFFF000000000000ULL && flink != blink) {
            uint64_t flinkBlink = 0;
            ULONG rdx = 0;
            if (SUCCEEDED(ds->ReadVirtual(flink + 8, &flinkBlink, 8, &rdx)) && rdx == 8) {
                if (flinkBlink == (headAddr + off) || flinkBlink == blink) {
                    listCandidates.push_back({ off, flink, blink });
                }
            }
        }
    }
    return listCandidates;
}

static std::wstring FormatAsciiPreview(
    IDebugDataSpaces4* ds,
    const std::vector<ULONG64>& instances,
    ULONG offset
) {
    std::wstring vals;
    size_t shown = 0;
    for (size_t i = 0; i < instances.size() && shown < 3; i++) {
        std::vector<uint8_t> b(8);
        ULONG rr = 0;
        if (SUCCEEDED(ds->ReadVirtual(instances[i] + offset, b.data(), 8, &rr))) {
            std::wstring s;
            for (auto c : b) {
                if (c >= 0x20 && c <= 0x7E) s += static_cast<wchar_t>(c);
                else break;
            }
            if (!s.empty()) {
                if (!vals.empty()) vals += L"|";
                vals += L"\"" + s + L"\"";
                shown++;
            }
        }
    }
    return vals;
}

static std::wstring FormatProfileAnnotation(
    IDebugSymbols4* sym,
    IDebugDataSpaces4* ds,
    const OffsetProfile& prof,
    const std::vector<ULONG64>& instances
) {
    if (prof.dominantType == FieldType::Pointer) {
        for (uint64_t v : prof.rawValues) {
            if (v > 0xFFFF000000000000ULL) {
                wchar_t sn[256] = {};
                ULONG64 d = 0;
                if (SUCCEEDED(sym->GetNameByOffsetWide(v, sn, _countof(sn), nullptr, &d))) {
                    std::wstring ann = sn;
                    if (d) ann += L"+...";
                    ann += L" (varies)";
                    return ann;
                }
            }
        }
    } else if (prof.dominantType == FieldType::AsciiString) {
        return FormatAsciiPreview(ds, instances, prof.offset);
    }
    return L"";
}

static ULONG PrintProfileTable(
    IDebugControl4* ctrl,
    IDebugSymbols4* sym,
    IDebugDataSpaces4* ds,
    const std::vector<OffsetProfile>& profiles,
    const std::vector<ULONG64>& instances
) {
    ULONG reported = 0;
    for (const auto& prof : profiles) {
        if (!prof.isInteresting) continue;

        std::vector<uint64_t> sorted = prof.rawValues;
        std::sort(sorted.begin(), sorted.end());
        size_t uniqueVals = std::unique(sorted.begin(), sorted.end()) - sorted.begin();

        std::wstring annotation = FormatProfileAnnotation(sym, ds, prof, instances);

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
    return reported;
}

HRESULT DoListCrossRef(
    const DebugContext& ctx,
    const wchar_t*      target,
    ULONG               scanWindow
) {
    ULONG64 headAddr = ResolveTarget(ctx.sym, target, nullptr);
    if (headAddr == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] LIST_ENTRY head: 0x%016llx\n",
        static_cast<unsigned long long>(headAddr));

    std::vector<uint8_t> buf0(scanWindow);
    ULONG rd0 = 0;
    if (FAILED(ctx.ds->ReadVirtual(headAddr, buf0.data(), scanWindow, &rd0)) || rd0 < 16) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot read head object\n");
        return E_FAIL;
    }

    auto listCandidates = FindListCandidates(ctx.ds, buf0.data(), rd0, headAddr);
    if (listCandidates.empty()) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[-] No valid LIST_ENTRY found in object. Try !structscan <sym> first to locate list offsets.\n");
        return E_FAIL;
    }

    for (const auto& le : listCandidates) {
        wchar_t symBuf[256] = {};
        ULONG64 disp = 0;
        std::wstring leAnnot;
        if (SUCCEEDED(ctx.sym->GetNameByOffsetWide(le.flink, symBuf, _countof(symBuf), nullptr, &disp))) {
            leAnnot = symBuf;
        }

        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Detected LIST_ENTRY at struct+0x%04lx  Flink->%s\n",
            static_cast<unsigned long>(le.offset),
            leAnnot.empty() ? L"<no symbol>" : leAnnot.c_str());
    }

    const auto& best = listCandidates[0];
    ULONG64 leHead = headAddr + best.offset;
    std::vector<ULONG64> instances = CrossRefEngine::WalkListEntry(ctx.ds, leHead, best.offset, 64);

    if (instances.empty()) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] List appears empty or head == self\n");
        return S_OK;
    }
    instances.insert(instances.begin(), headAddr);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Collected %llu struct instances for cross-reference analysis\n\n",
        static_cast<unsigned long long>(instances.size()));

    auto profiles = CrossRefEngine::AnalyzeListProfiles(ctx.ds, ctx.sym, instances, scanWindow);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    Type              Consistency  Unique Values  Annotation\n"
        L"  --------  ----------------  -----------  -------------  --------------------------------\n");

    ULONG reported = PrintProfileTable(ctx.ctrl, ctx.sym, ctx.ds, profiles, instances);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Cross-reference complete: %lu consistent fields identified across %llu instances\n",
        static_cast<unsigned long>(reported),
        static_cast<unsigned long long>(instances.size()));
    return S_OK;
}
