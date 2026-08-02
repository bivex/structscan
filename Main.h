/**
 * @file Main.h
 * @brief StructScan WinDbg Extension — Advanced Non-Symbol Structure Scanner
 * @author Modernized C++17 Architecture
 * @date 2026-08-02
 */

#ifndef STRUCTSCAN_MAIN_H
#define STRUCTSCAN_MAIN_H

#define INITGUID
#include <windows.h>
#include <dbgeng.h>
#include <string>
#include <vector>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

// EngHost entry point
__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags);

// Extension command: !structscan <module!symbol_or_address> [max_offset_hex]
__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args);

#ifdef __cplusplus
}
#endif

/**
 * @class OutputCaptureCallback
 * @brief Clean RAII Debugger Output Interceptor for WinDbg DbgEng
 */
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
        if (m_client) {
            m_client->SetOutputCallbacks(m_prevCallback);
        }
    }

    ~OutputCaptureCallback() { Restore(); }

    void Clear() { m_capturedOutput.clear(); }
    const std::wstring& GetOutput() const { return m_capturedOutput; }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID InterfaceId, PVOID* Interface) override {
        if (InterfaceId == __uuidof(IUnknown) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks2)) {
            *Interface = static_cast<IDebugOutputCallbacks2*>(this);
            AddRef();
            return S_OK;
        }
        *Interface = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return ++m_refCount; }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG count = --m_refCount;
        if (count == 0) delete this;
        return count;
    }

    // IDebugOutputCallbacks
    STDMETHODIMP Output(ULONG Mask, PCSTR Text) override {
        if (Text) {
            int wideLen = MultiByteToWideChar(CP_ACP, 0, Text, -1, nullptr, 0);
            if (wideLen > 0) {
                std::vector<wchar_t> wbuf(wideLen);
                MultiByteToWideChar(CP_ACP, 0, Text, -1, wbuf.data(), wideLen);
                m_capturedOutput += wbuf.data();
            }
        }
        return S_OK;
    }

    // IDebugOutputCallbacks2
    STDMETHODIMP GetInterestMask(PULONG Mask) override {
        if (Mask) *Mask = DEBUG_OUTCBI_ANY_FORMAT;
        return S_OK;
    }

    STDMETHODIMP Output2(ULONG Which, ULONG Flags, ULONG64 Arg, PCWSTR Text) override {
        if (Text) {
            m_capturedOutput += Text;
        }
        return S_OK;
    }
};

#endif // STRUCTSCAN_MAIN_H