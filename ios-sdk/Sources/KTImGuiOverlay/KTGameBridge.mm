// ios-sdk/Sources/KTImGuiOverlay/KTGameBridge.mm
#import "KTGameBridge.h"
#include <atomic>
#include <cstring>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>

namespace ktbridge {

static std::atomic<bool> sMonitorInstalled{false};
static std::atomic<uintptr_t> sUnityBase{0};
static std::atomic<intptr_t> sUnitySlide{0};
static std::atomic<uintptr_t> sTextStart{0};
static std::atomic<size_t> sTextSize{0};

static AntibanVector sVectors[12] = {
    {9,  "[9]  CChatNetUT::On_Chat_Complaint_NTF", "CChatNetUT", "On_Chat_Complaint_NTF", 0, 0, false},
    {10, "[10] CmdPkg::get_PrmPlayerCheat", "CmdPkg", "get_PrmPlayerCheat", 0, 0, false},
    {11, "[11] CSDT_CHEATCMD_DETAIL::get_stCheatPushMsgToFirebase", "CSDT_CHEATCMD_DETAIL", "get_stCheatPushMsgToFirebase", 0, 0, false},
    {12, "[12] LFrameSyncBattleLogic::SampleAndSendFrameSyncData", "LFrameSyncBattleLogic", "SampleAndSendFrameSyncData", 0, 0, false},
    {13, "[13] LFramework::get_SynchrReport", "LFramework", "get_SynchrReport", 0, 0, false},
    {14, "[14] EchoPing::ReportSvrStateToSvr", "EchoPing", "ReportSvrStateToSvr", 0, 0, false},
    {15, "[15] LobbyMsgHandler::onTriggerSecurityDataReport", "LobbyMsgHandler", "onTriggerSecurityDataReport", 0, 0, false},
    {16, "[16] LobbyMsgHandler::onGameLoginAntidataEvent", "LobbyMsgHandler", "onGameLoginAntidataEvent", 0, 0, false},
    {17, "[17] ApolloEventReport::ReportEventPlayerInfo", "ApolloEventReport", "ReportEventPlayerInfo", 0, 0, false},
    {18, "[18] LFrameSynchr::UpdateFrameLater", "LFrameSynchr", "UpdateFrameLater", 0, 0, false},
    {19, "[19] LFrameSyncBattleLogic::SendSyncData", "LFrameSyncBattleLogic", "SendSyncData", 0, 0, false},
    {20, "[20] DualChannelHelper::CheckDeviceInBlackList", "DualChannelHelper", "CheckDeviceInBlackList", 0, 0, false}
};

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
                InstallAntibanSuppressors();
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

static bool PatchArm64ReturnZero(uintptr_t addr) {
    if (addr == 0) return false;
    vm_address_t page = addr & ~static_cast<vm_address_t>(PAGE_SIZE - 1);
    vm_size_t size = PAGE_SIZE * 2;
    kern_return_t kr = vm_protect(mach_task_self(), page, size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return false;

    // mov w0, #0 (0x52800000), ret (0xd65f03c0)
    uint32_t *target = reinterpret_cast<uint32_t *>(addr);
    target[0] = 0x52800000;
    target[1] = 0xd65f03c0;

    vm_protect(mach_task_self(), page, size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(reinterpret_cast<void *>(addr), 8);
    return true;
}

const AntibanVector *GetAntibanVectors(size_t *outCount) {
    if (outCount) *outCount = 12;
    return sVectors;
}

void InstallAntibanSuppressors() {
    uintptr_t base = sUnityBase.load(std::memory_order_acquire);
    intptr_t slide = sUnitySlide.load(std::memory_order_acquire);
    if (base == 0) return;

    for (int i = 0; i < 12; ++i) {
        AntibanVector &v = sVectors[i];
        if (v.active) continue;

        // Try direct symbol resolve first
        char sym[128];
        std::snprintf(sym, sizeof(sym), "%s_%s", v.className, v.methodName);
        void *p = ResolveIL2CPPSymbol(sym);
        if (!p) {
            std::snprintf(sym, sizeof(sym), "_%s_%s", v.className, v.methodName);
            p = ResolveIL2CPPSymbol(sym);
        }

        if (p) {
            v.targetVA = reinterpret_cast<uintptr_t>(p);
            v.rva = v.targetVA - base;
            if (v.index == 10 || v.index == 11 || v.index == 15 || v.index == 16 || v.index == 17 || v.index == 20) {
                // Suppress telemetry and report transmissions
                v.active = PatchArm64ReturnZero(v.targetVA);
            } else {
                v.active = true;
            }
        }
    }
}

} // namespace ktbridge
