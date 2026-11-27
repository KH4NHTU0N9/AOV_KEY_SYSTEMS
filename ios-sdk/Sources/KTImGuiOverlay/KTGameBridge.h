// ios-sdk/Sources/KTImGuiOverlay/KTGameBridge.h
#pragma once
#include <cstddef>
#include <cstdint>

namespace ktbridge {

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

} // namespace ktbridge
