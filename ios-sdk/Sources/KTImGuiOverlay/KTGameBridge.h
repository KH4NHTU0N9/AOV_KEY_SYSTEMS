// ios-sdk/Sources/KTImGuiOverlay/KTGameBridge.h
#pragma once
#include <cstddef>
#include <cstdint>

namespace ktbridge {

enum class AntibanState : uint8_t {
    Pending = 0,
    Suppressed = 1, // Statically patched RET / return 0
    Hooked = 2,     // Trampoline hook active in __TEXT cave
    Monitored = 3   // Telemetry/packet structure monitored
};

struct AntibanVector {
    int index;
    const char *label;
    const char *className;
    const char *methodName;
    uintptr_t rva;
    uintptr_t targetVA;
    AntibanState state;
};

/// Registers a dyld image-add callback using lock-safe atomic writes for UnityFramework.
void InstallDyldMonitor();

/// Returns true once UnityFramework has been mapped into process memory.
bool IsUnityFrameworkLoaded();

/// Returns the runtime base address and ASLR slide of UnityFramework.
uintptr_t GetUnityBaseAddress();
intptr_t GetUnityASLRSlide();

/// Dynamically resolves an exported il2cpp C API symbol (may return nullptr on stripped builds).
void *ResolveIL2CPPSymbol(const char *symbolName);

/// Searches UnityFramework __TEXT,__text for a masked byte pattern (AOB fallback when symbols are stripped).
uintptr_t ScanTextPattern(const uint8_t *pattern, const char *mask, size_t length);

/// Returns the 12 telemetry and security vectors resolved from global-metadata.dat.
const AntibanVector *GetAntibanVectors(size_t *outCount);

/// Resolves runtime VAs and inspects active memory patches/hooks across all 12 vectors.
void RefreshAntibanStatus();

} // namespace ktbridge
