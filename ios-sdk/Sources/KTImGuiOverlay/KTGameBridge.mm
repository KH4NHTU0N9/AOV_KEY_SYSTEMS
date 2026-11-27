// ios-sdk/Sources/KTImGuiOverlay/KTGameBridge.mm
#import "KTGameBridge.h"
#include <atomic>
#include <cstring>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

namespace ktbridge {

static std::atomic<bool> sMonitorInstalled{false};
static std::atomic<uintptr_t> sUnityBase{0};
static std::atomic<intptr_t> sUnitySlide{0};
static std::atomic<uintptr_t> sTextStart{0};
static std::atomic<size_t> sTextSize{0};

static void InspectImage(const struct mach_header *mh, intptr_t vmaddr_slide) {
    if (!mh) return;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        if (_dyld_get_image_header(i) == mh) {
            const char *name = _dyld_get_image_name(i);
            if (name && std::strstr(name, "UnityFramework") != nullptr) {
                sUnityBase.store(reinterpret_cast<uintptr_t>(mh), std::memory_order_release);
                sUnitySlide.store(vmaddr_slide, std::memory_order_release);

                if (mh->magic == MH_MAGIC_64) {
                    const auto *mh64 = reinterpret_cast<const struct mach_header_64 *>(mh);
                    const uint8_t *cmdPtr = reinterpret_cast<const uint8_t *>(mh64 + 1);
                    for (uint32_t c = 0; c < mh64->ncmds; ++c) {
                        const auto *lc = reinterpret_cast<const struct load_command *>(cmdPtr);
                        if (lc->cmd == LC_SEGMENT_64) {
                            const auto *seg = reinterpret_cast<const struct segment_command_64 *>(cmdPtr);
                            if (std::strncmp(seg->segname, "__TEXT", 16) == 0) {
                                sTextStart.store(static_cast<uintptr_t>(seg->vmaddr + vmaddr_slide), std::memory_order_release);
                                sTextSize.store(static_cast<size_t>(seg->vmsize), std::memory_order_release);
                                break;
                            }
                        }
                        cmdPtr += lc->cmdsize;
                    }
                }
            }
            break;
        }
    }
}

void InstallDyldMonitor() {
    bool expected = false;
    if (!sMonitorInstalled.compare_exchange_strong(expected, true)) {
        return;
    }
    // Never invoke ObjC/Swift inside dyld callback; InspectImage uses pure C + atomics only.
    _dyld_register_func_for_add_image(InspectImage);
}

bool IsUnityFrameworkLoaded() {
    return sUnityBase.load(std::memory_order_acquire) != 0;
}

uintptr_t GetUnityBaseAddress() {
    return sUnityBase.load(std::memory_order_acquire);
}

intptr_t GetUnityASLRSlide() {
    return sUnitySlide.load(std::memory_order_acquire);
}

void *ResolveIL2CPPSymbol(const char *symbolName) {
    if (!symbolName) return nullptr;
    return dlsym(RTLD_DEFAULT, symbolName);
}

uintptr_t ScanTextPattern(const uint8_t *pattern, const char *mask, size_t length) {
    uintptr_t start = sTextStart.load(std::memory_order_acquire);
    size_t size = sTextSize.load(std::memory_order_acquire);
    if (!pattern || !mask || length == 0 || start == 0 || size < length) {
        return 0;
    }
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(start);
    size_t limit = size - length;
    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < length; ++j) {
            if (mask[j] != '?' && bytes[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return start + i;
        }
    }
    return 0;
}

} // namespace ktbridge
