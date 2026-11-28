// ios-sdk/Sources/KTImGuiOverlay/KTGameBridge.mm
#import "KTGameBridge.h"
#include <atomic>
#include <cstdio>
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

// Exact RVAs extracted from kgvn.app global-metadata.dat (v29) + CodeGenModule methodPointers
static AntibanVector sVectors[12] = {
    {9,  "[9]  CChatNetUT::On_Chat_Complaint_NTF",                  "CChatNetUT",            "On_Chat_Complaint_NTF",        0x00f1997c, 0, AntibanState::Pending},
    {10, "[10] CmdPkg::get_PrmPlayerCheat",                        "CmdPkg",                "get_PrmPlayerCheat",           0x0041f6b4, 0, AntibanState::Pending},
    {11, "[11] CSDT_CHEATCMD_DETAIL::get_stCheatPushMsgToFirebase","CSDT_CHEATCMD_DETAIL",  "get_stCheatPushMsgToFirebase", 0x008d3138, 0, AntibanState::Pending},
    {12, "[12] LFrameSyncBattleLogic::SampleAndSendFrameSyncData", "LFrameSyncBattleLogic", "SampleAndSendFrameSyncData",   0x04bf931c, 0, AntibanState::Pending},
    {13, "[13] LFramework::get_SynchrReport",                      "LFramework",            "get_SynchrReport",             0x04e05a3c, 0, AntibanState::Pending},
    {14, "[14] EchoPing::ReportSvrStateToSvr",                     "EchoPing",              "ReportSvrStateToSvr",          0x05cc2888, 0, AntibanState::Pending},
    {15, "[15] LobbyMsgHandler::onTriggerSecurityDataReport",      "LobbyMsgHandler",       "onTriggerSecurityDataReport",  0x0677e2a4, 0, AntibanState::Pending},
    {16, "[16] LobbyMsgHandler::onGameLoginAntidataEvent",         "LobbyMsgHandler",       "onGameLoginAntidataEvent",     0x0677e424, 0, AntibanState::Pending},
    {17, "[17] ApolloEventReport::ReportEventPlayerInfo",          "ApolloEventReport",     "ReportEventPlayerInfo",        0x05b78370, 0, AntibanState::Pending},
    {18, "[18] LFrameSynchr::UpdateFrameLater",                    "LFrameSynchr",          "UpdateFrameLater",             0x04d9a59c, 0, AntibanState::Pending},
    {19, "[19] LFrameSyncBattleLogic::SendSyncData",               "LFrameSyncBattleLogic", "SendSyncData",                 0x04bf95b8, 0, AntibanState::Pending},
    {20, "[20] DualChannelHelper::CheckDeviceInBlackList",         "DualChannelHelper",     "CheckDeviceInBlackList",       0x05b7ddd8, 0, AntibanState::Pending}
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
    // Pure C + atomics only inside dyld callback
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

void RefreshAntibanStatus() {
    uintptr_t textStart = sTextStart.load(std::memory_order_acquire);
    size_t textSize = sTextSize.load(std::memory_order_acquire);
    uintptr_t base = sUnityBase.load(std::memory_order_acquire);
    if (base == 0 || textStart == 0 || textSize == 0) return;

    for (int i = 0; i < 12; ++i) {
        AntibanVector &v = sVectors[i];
        uintptr_t va = base + v.rva;
        v.targetVA = va;

        if (va >= textStart && va + 8 <= textStart + textSize) {
            const uint32_t *insns = reinterpret_cast<const uint32_t *>(va);
            uint32_t op0 = insns[0];
            uint32_t op1 = insns[1];

            // RET (0xd65f03c0) or MOV W0/X0, #0 + RET (0x52800000 / 0xd2800000 + 0xd65f03c0)
            if (op0 == 0xd65f03c0 ||
                ((op0 == 0x52800000 || op0 == 0xd2800000) && op1 == 0xd65f03c0)) {
                v.state = AntibanState::Suppressed;
            } else if ((op0 & 0xfc000000) == 0x14000000 || // B immediate trampoline
                       ((op0 & 0x9f00001f) == 0x90000011 && (insns[2] == 0xd61f0220))) { // ADRP X17; ADD X17; BR X17
                v.state = AntibanState::Hooked;
            } else {
                v.state = AntibanState::Monitored;
            }
        }
    }
}

const AntibanVector *GetAntibanVectors(size_t *outCount) {
    RefreshAntibanStatus();
    if (outCount) *outCount = 12;
    return sVectors;
}

} // namespace ktbridge
