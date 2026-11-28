// ios-sdk/Sources/KTImGuiOverlay/KTImGuiOverlay.mm
#import "include/KTImGuiOverlay.h"
#import "KTGameBridge.h"
#import <TargetConditionals.h>

#if TARGET_OS_IPHONE && __has_include(<UIKit/UIKit.h>) && __has_include(<Metal/Metal.h>) && __has_include(<MetalKit/MetalKit.h>) && __has_include("imgui.h")
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>
#import <QuartzCore/QuartzCore.h>
#import "KTImGuiFonts.hpp"
#include "imgui.h"
#include "imgui_impl_metal.h"

static NSString *const kPrefPosX = @"ktaov.bubble.x";
static NSString *const kPrefPosY = @"ktaov.bubble.y";
static NSString *const kPrefPillsX = @"ktaov.pills.x";
static NSString *const kPrefPillsY = @"ktaov.pills.y";
static NSString *const kPrefStreamProof = @"ktaov.streamproof";
static NSString *const kPrefShowPills = @"ktaov.show_pills";
static NSString *const kPrefAlpha = @"ktaov.panel_alpha";

@interface KTHideCaptureWrapper : UIView
@property (nonatomic, strong, nullable) UIView *protectedContainer;
- (void)setCaptureHidden:(BOOL)hidden;
@end

@interface KTSecurePassField : UITextField
@end

@implementation KTSecurePassField
- (BOOL)canBecomeFirstResponder { return NO; }
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self) ? nil : hit;
}
@end

@implementation KTHideCaptureWrapper {
    KTSecurePassField *_secureField;
    UIView *_normalContainer;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.backgroundColor = [UIColor clearColor];
        self.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        _normalContainer = [[UIView alloc] initWithFrame:self.bounds];
        _normalContainer.backgroundColor = [UIColor clearColor];
        _normalContainer.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self addSubview:_normalContainer];
        _protectedContainer = _normalContainer;
    }
    return self;
}

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self || hit == _normalContainer) ? nil : hit;
}

- (void)setCaptureHidden:(BOOL)hidden {
    if (!hidden) {
        if (_secureField) {
            for (UIView *sub in [_protectedContainer.subviews copy]) {
                [_normalContainer addSubview:sub];
            }
            [_secureField removeFromSuperview];
            _secureField = nil;
        }
        _protectedContainer = _normalContainer;
        return;
    }

    if (!_secureField) {
        _secureField = [[KTSecurePassField alloc] initWithFrame:self.bounds];
        _secureField.secureTextEntry = YES;
        _secureField.backgroundColor = [UIColor clearColor];
        _secureField.userInteractionEnabled = YES;
        _secureField.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;

        UIView *canvas = nil;
        for (UIView *sub in _secureField.subviews) {
            NSString *cls = NSStringFromClass([sub class]);
            if ([cls containsString:@"TextLayoutCanvas"] || [cls containsString:@"CanvasView"]) {
                canvas = sub;
                break;
            }
        }
        if (!canvas) {
            canvas = _secureField.subviews.firstObject;
        }
        if (canvas) {
            canvas.userInteractionEnabled = YES;
            [self addSubview:_secureField];
            for (UIView *sub in [_normalContainer.subviews copy]) {
                [canvas addSubview:sub];
            }
            _protectedContainer = canvas;
        } else {
            // Safe fallback to normal view when iOS changes private UITextField subviews
            _secureField = nil;
            _protectedContainer = _normalContainer;
        }
    }
}
@end

@interface KTImGuiCanvasView : MTKView <MTKViewDelegate>
@property (nonatomic, assign) BOOL menuOpen;
@property (nonatomic, assign) BOOL showQuickPills;
@property (nonatomic, assign) BOOL streamProofEnabled;
@property (nonatomic, assign) float panelAlpha;
@property (nonatomic, assign) CGRect activePanelRect;
@property (nonatomic, assign) CGRect activePillsRect;
@property (nonatomic, copy) NSString *serverURL;
@property (nonatomic, copy) NSString *licenseKey;
@property (nonatomic, copy) NSString *deviceID;
@property (nonatomic, assign) double expiresAt;
@property (nonatomic, copy, nullable) NSString *getKeyURL;
@property (nonatomic, copy) void (^onStreamProofToggled)(BOOL enabled);
@property (nonatomic, copy) void (^onMenuClosed)(void);
@end

@interface KTOverlayWindow : UIWindow
@property (nonatomic, weak) KTImGuiCanvasView *canvasView;
@property (nonatomic, weak) UIButton *floatingButton;
@end

@implementation KTOverlayWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    if (self.floatingButton && !self.floatingButton.hidden &&
        CGRectContainsPoint(CGRectInset(self.floatingButton.frame, -6, -6), point)) {
        return [super hitTest:point withEvent:event];
    }
    if (self.canvasView && !self.canvasView.hidden) {
        if (self.canvasView.menuOpen &&
            !CGRectIsEmpty(self.canvasView.activePanelRect) &&
            CGRectContainsPoint(self.canvasView.activePanelRect, point)) {
            return [super hitTest:point withEvent:event];
        }
        if (self.canvasView.showQuickPills &&
            !CGRectIsEmpty(self.canvasView.activePillsRect) &&
            CGRectContainsPoint(self.canvasView.activePillsRect, point)) {
            return [super hitTest:point withEvent:event];
        }
    }
    return nil;
}
@end

@implementation KTImGuiCanvasView {
    id<MTLCommandQueue> _commandQueue;
    ImGuiContext *_imguiCtx;
    int _selectedTab;
    BOOL _safeSkinMode;
    BOOL _pillQuickAim;
    BOOL _pillQuickSell;
    BOOL _inBackground;
    double _lastFrameTime;
}

- (instancetype)initWithFrame:(CGRect)frame {
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    self = [super initWithFrame:frame device:dev];
    if (self && dev) {
        self.delegate = self;
        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        self.layer.opaque = NO;
        self.clearColor = MTLClearColorMake(0.0, 0.0, 0.0, 0.0);
        self.colorPixelFormat = MTLPixelFormatBGRA8Unorm;
        self.paused = YES;
        self.enableSetNeedsDisplay = NO;
        self.multipleTouchEnabled = YES;

        _commandQueue = [dev newCommandQueue];
        _imguiCtx = ImGui::CreateContext();
        ImGui::SetCurrentContext(_imguiCtx);

        ImGuiIO &io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;

        ImFontConfig fontCfg;
        fontCfg.FontDataOwnedByAtlas = false;
        io.Fonts->AddFontFromMemoryTTF(
            (void *)kBeVietnamProTTF,
            (int)kBeVietnamProTTFSize,
            15.5f,
            &fontCfg,
            io.Fonts->GetGlyphRangesVietnamese()
        );

        [self applyLiquidDarkTheme];
        ImGui_ImplMetal_Init(dev);

        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        _panelAlpha = [ud objectForKey:kPrefAlpha] ? [ud floatForKey:kPrefAlpha] : 0.92f;
        _showQuickPills = [ud boolForKey:kPrefShowPills];
        _streamProofEnabled = [ud boolForKey:kPrefStreamProof];
        _safeSkinMode = YES;
        _activePanelRect = CGRectZero;
        _activePillsRect = CGRectZero;
        _lastFrameTime = CACurrentMediaTime();
    }
    return self;
}

- (void)dealloc {
    if (_imguiCtx) {
        ImGui::SetCurrentContext(_imguiCtx);
        ImGui_ImplMetal_Shutdown();
        ImGui::DestroyContext(_imguiCtx);
        _imguiCtx = nullptr;
    }
}

- (void)applyLiquidDarkTheme {
    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.WindowRounding = 14.0f;
    style.ChildRounding = 10.0f;
    style.FrameRounding = 8.0f;
    style.GrabRounding = 8.0f;
    style.PopupRounding = 10.0f;
    style.WindowBorderSize = 1.0f;
    style.FramePadding = ImVec2(10.0f, 7.0f);
    style.ItemSpacing = ImVec2(8.0f, 8.0f);

    ImVec4 *c = style.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.08f, 0.14f, 0.94f);
    c[ImGuiCol_Border] = ImVec4(0.39f, 0.40f, 0.95f, 0.45f);
    c[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.10f, 0.18f, 1.0f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.14f, 0.16f, 0.30f, 1.0f);
    c[ImGuiCol_Button] = ImVec4(0.35f, 0.37f, 0.92f, 0.85f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.45f, 0.47f, 0.98f, 1.0f);
    c[ImGuiCol_FrameBg] = ImVec4(0.11f, 0.14f, 0.23f, 1.0f);
    c[ImGuiCol_CheckMark] = ImVec4(0.22f, 0.74f, 0.97f, 1.0f);
}

- (void)updateRenderPauseState {
    BOOL shouldRun = (!_inBackground) && (_menuOpen || _showQuickPills);
    self.hidden = !shouldRun;
    self.paused = !shouldRun;
}

- (void)setMenuOpen:(BOOL)menuOpen {
    _menuOpen = menuOpen;
    if (!menuOpen) {
        _activePanelRect = CGRectZero;
    }
    [self updateRenderPauseState];
}

- (void)setShowQuickPills:(BOOL)showQuickPills {
    _showQuickPills = showQuickPills;
    if (!showQuickPills) {
        _activePillsRect = CGRectZero;
    }
    [self updateRenderPauseState];
}

- (void)setEnteredBackground:(BOOL)bg {
    _inBackground = bg;
    [self updateRenderPauseState];
}

#pragma mark - UITouch Mapping for Dear ImGui
- (void)dispatchTouch:(UITouch *)touch down:(BOOL)isDown hasDownValue:(BOOL)hasDownValue {
    if (!_imguiCtx) return;
    ImGui::SetCurrentContext(_imguiCtx);
    ImGuiIO &io = ImGui::GetIO();
    CGPoint pt = [touch locationInView:self];
    io.AddMousePosEvent((float)pt.x, (float)pt.y);
    if (hasDownValue) {
        io.AddMouseButtonEvent(0, isDown);
    }
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (t) [self dispatchTouch:t down:YES hasDownValue:YES];
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (t) [self dispatchTouch:t down:YES hasDownValue:NO];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (t) [self dispatchTouch:t down:NO hasDownValue:YES];
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (t) [self dispatchTouch:t down:NO hasDownValue:YES];
}

#pragma mark - MTKViewDelegate
- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {}

- (void)drawInMTKView:(MTKView *)view {
    if (_inBackground || (!_menuOpen && !_showQuickPills)) {
        return;
    }
    id<CAMetalDrawable> drawable = view.currentDrawable;
    MTLRenderPassDescriptor *rpd = view.currentRenderPassDescriptor;
    if (!drawable || !rpd) return;

    id<MTLCommandBuffer> cmdBuf = [_commandQueue commandBuffer];
    id<MTLRenderCommandEncoder> enc = [cmdBuf renderCommandEncoderWithDescriptor:rpd];

    ImGui::SetCurrentContext(_imguiCtx);
    ImGuiIO &io = ImGui::GetIO();
    CGSize bounds = self.bounds.size;
    CGFloat scale = self.contentScaleFactor > 0 ? self.contentScaleFactor : [UIScreen mainScreen].scale;
    io.DisplaySize = ImVec2((float)bounds.width, (float)bounds.height);
    io.DisplayFramebufferScale = ImVec2((float)scale, (float)scale);

    double now = CACurrentMediaTime();
    io.DeltaTime = (float)fmax(1.0 / 120.0, fmin(0.1, now - _lastFrameTime));
    _lastFrameTime = now;

    ImGui_ImplMetal_NewFrame(rpd);
    ImGui::NewFrame();

    UIEdgeInsets safe = UIEdgeInsetsZero;
    if (@available(iOS 11.0, *)) {
        safe = self.safeAreaInsets;
    }

    if (_menuOpen) {
        CGFloat panelW = fmin(420.0, bounds.width - safe.left - safe.right - 24.0);
        CGFloat panelH = fmin(340.0, bounds.height - safe.top - safe.bottom - 24.0);
        ImGui::SetNextWindowSize(ImVec2((float)panelW, (float)panelH), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(
            ImVec2((float)((bounds.width - panelW) * 0.5), (float)fmax(safe.top + 12.0, (bounds.height - panelH) * 0.5)),
            ImGuiCond_FirstUseEver
        );
        ImGui::SetNextWindowBgAlpha(_panelAlpha);

        bool openFlag = true;
        if (ImGui::Begin("KT AOV • Metal UI", &openFlag, ImGuiWindowFlags_NoCollapse)) {
            ImVec2 wPos = ImGui::GetWindowPos();
            ImVec2 wSize = ImGui::GetWindowSize();
            _activePanelRect = CGRectMake(wPos.x, wPos.y, wSize.x, wSize.y);

            const char *tabs[] = {"Tổng quan & Key", "Giao diện", "Tiện ích", "Bảo vệ (Antiban)", "GameBridge"};
            for (int i = 0; i < 5; ++i) {
                if (i > 0) ImGui::SameLine();
                if (_selectedTab == i) {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.22f, 0.74f, 0.97f, 0.9f));
                }
                if (ImGui::Button(tabs[i])) {
                    _selectedTab = i;
                }
                if (_selectedTab == i) {
                    ImGui::PopStyleColor();
                }
            }
            ImGui::Separator();

            if (_selectedTab == 0) {
                double remain = fmax(0.0, _expiresAt - [[NSDate date] timeIntervalSince1970]);
                int hrs = (int)(remain / 3600.0);
                int mins = ((int)remain % 3600) / 60;
                ImGui::Text("Trạng thái: Đã xác thực Ed25519");
                ImGui::Text("Key: %s", _licenseKey.UTF8String ?: "-");
                ImGui::Text("Thời hạn còn lại: %d giờ %d phút", hrs, mins);
                ImGui::TextWrapped("Device ID: %s", _deviceID.UTF8String ?: "-");
                if (ImGui::Button("Copy Device ID")) {
                    [UIPasteboard generalPasteboard].string = _deviceID ?: @"";
                }
                if (_getKeyURL.length > 0) {
                    ImGui::SameLine();
                    if (ImGui::Button("Mở trang Get Key")) {
                        NSURL *u = [NSURL URLWithString:_getKeyURL];
                        if (u) [[UIApplication sharedApplication] openURL:u options:@{} completionHandler:nil];
                    }
                }
            } else if (_selectedTab == 1) {
                if (ImGui::SliderFloat("Độ mờ nền", &_panelAlpha, 0.45f, 1.0f)) {
                    [[NSUserDefaults standardUserDefaults] setFloat:_panelAlpha forKey:kPrefAlpha];
                }
                bool sp = _streamProofEnabled;
                if (ImGui::Checkbox("Ẩn khi quay màn hình (iOS)", &sp)) {
                    _streamProofEnabled = sp;
                    [[NSUserDefaults standardUserDefaults] setBool:sp forKey:kPrefStreamProof];
                    if (self.onStreamProofToggled) self.onStreamProofToggled(sp);
                }
                bool pills = _showQuickPills;
                if (ImGui::Checkbox("Hiện thanh Quick Action Pills", &pills)) {
                    self.showQuickPills = pills;
                    [[NSUserDefaults standardUserDefaults] setBool:pills forKey:kPrefShowPills];
                }
            } else if (_selectedTab == 2) {
                bool safeMode = _safeSkinMode;
                if (ImGui::Checkbox("Chế độ an toàn (Catalog sạch)", &safeMode)) {
                    _safeSkinMode = safeMode;
                }
                ImGui::TextWrapped("Nguồn catalog: https://raw.githubusercontent.com/KH4NHTU0N9/aov/main/data.json");
                ImGui::Checkbox("Quick Pill: Aim", &_pillQuickAim);
                ImGui::Checkbox("Quick Pill: Auto Bán Đồ", &_pillQuickSell);
            } else if (_selectedTab == 3) {
                ImGui::Text("Bảo vệ Telemetry & Blacklist (12 vector từ thamkhao)");
                ImGui::Text("ASLR Unity: 0x%llX", (unsigned long long)ktbridge::GetUnityASLRSlide());
                if (ImGui::BeginTable("##antiban_tbl", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 190.0f))) {
                    ImGui::TableSetupColumn("Index", ImGuiTableColumnFlags_WidthFixed, 42.0f);
                    ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("VA (abs)", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Trạng thái", ImGuiTableColumnFlags_WidthFixed, 75.0f);
                    ImGui::TableHeadersRow();

                    size_t count = 0;
                    const ktbridge::AntibanVector *vecs = ktbridge::GetAntibanVectors(&count);
                    for (size_t i = 0; i < count; ++i) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("[%d]", vecs[i].index);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(vecs[i].label);
                        ImGui::TableSetColumnIndex(2);
                        if (vecs[i].targetVA != 0) {
                            ImGui::Text("0x%llX", (unsigned long long)vecs[i].targetVA);
                        } else {
                            ImGui::TextDisabled("NULL");
                        }
                        ImGui::TableSetColumnIndex(3);
                        switch (vecs[i].state) {
                            case ktbridge::AntibanState::Suppressed:
                                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.35f, 1.0f), "Đã triệt tiêu");
                                break;
                            case ktbridge::AntibanState::Hooked:
                                ImGui::TextColored(ImVec4(0.22f, 0.74f, 0.97f, 1.0f), "Đã Hook");
                                break;
                            case ktbridge::AntibanState::Monitored:
                                ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.2f, 1.0f), "Theo dõi");
                                break;
                            default:
                                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Chờ Unity");
                                break;
                        }
                    }
                    ImGui::EndTable();
                }
            } else {
                ImGui::Text("UnityFramework: %s", ktbridge::IsUnityFrameworkLoaded() ? "Đã nạp" : "Chưa phát hiện");
                ImGui::Text("Base Addr: 0x%lx", (unsigned long)ktbridge::GetUnityBaseAddress());
                ImGui::Text("ASLR Slide: 0x%lx", (unsigned long)ktbridge::GetUnityASLRSlide());
                ImGui::TextWrapped("Gợi ý: Mùa game mới chỉ cần cập nhật offset/AOB scan trong KTGameBridge.mm và build lại bằng GitHub Actions.");
            }
        }
        ImGui::End();

        if (!openFlag) {
            self.menuOpen = NO;
            if (self.onMenuClosed) self.onMenuClosed();
        }
    }

    if (_showQuickPills) {
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        float px = [ud objectForKey:kPrefPillsX] ? [ud floatForKey:kPrefPillsX] : (float)(safe.left + 16.0);
        float py = [ud objectForKey:kPrefPillsY] ? [ud floatForKey:kPrefPillsY] : (float)(bounds.height - safe.bottom - 72.0);
        ImGui::SetNextWindowPos(ImVec2(px, py), ImGuiCond_FirstUseEver);
        ImGuiWindowFlags flags = ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoTitleBar;
        if (ImGui::Begin("##KTQuickPills", nullptr, flags)) {
            ImVec2 pPos = ImGui::GetWindowPos();
            ImVec2 pSize = ImGui::GetWindowSize();
            _activePillsRect = CGRectMake(pPos.x, pPos.y, pSize.x, pSize.y);
            [ud setFloat:pPos.x forKey:kPrefPillsX];
            [ud setFloat:pPos.y forKey:kPrefPillsY];

            if (ImGui::Button(_pillQuickAim ? "Aim: ON" : "Aim: OFF")) {
                _pillQuickAim = !_pillQuickAim;
            }
            ImGui::SameLine();
            if (ImGui::Button(_pillQuickSell ? "Bán Đồ: ON" : "Bán Đồ: OFF")) {
                _pillQuickSell = !_pillQuickSell;
            }
        }
        ImGui::End();
    }

    ImGui::Render();
    ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), cmdBuf, enc);
    [enc endEncoding];
    [cmdBuf presentDrawable:drawable];
    [cmdBuf commit];
}
@end

static KTOverlayWindow *sOverlayWindow = nil;
static KTHideCaptureWrapper *sCaptureWrapper = nil;
static KTImGuiCanvasView *sCanvas = nil;
static UIButton *sFloatingBtn = nil;
static id sBgObserver = nil;
static id sFgObserver = nil;

@interface KTImGuiDragHelper : NSObject
+ (void)onTapFloating:(UIButton *)sender;
+ (void)onPanFloating:(UIPanGestureRecognizer *)pan;
@end

@implementation KTImGuiDragHelper
+ (void)onTapFloating:(UIButton *)sender {
    if (!sCanvas) return;
    sCanvas.menuOpen = !sCanvas.menuOpen;
}

+ (void)onPanFloating:(UIPanGestureRecognizer *)pan {
    if (!sOverlayWindow || !sFloatingBtn) return;
    CGPoint delta = [pan translationInView:sOverlayWindow];
    [pan setTranslation:CGPointZero inView:sOverlayWindow];
    CGRect bounds = sOverlayWindow.bounds;
    UIEdgeInsets safe = UIEdgeInsetsZero;
    if (@available(iOS 11.0, *)) {
        safe = sOverlayWindow.safeAreaInsets;
    }
    CGFloat halfW = sFloatingBtn.bounds.size.width * 0.5;
    CGFloat halfH = sFloatingBtn.bounds.size.height * 0.5;
    CGFloat nx = fmax(safe.left + halfW + 4, fmin(bounds.size.width - safe.right - halfW - 4, sFloatingBtn.center.x + delta.x));
    CGFloat ny = fmax(safe.top + halfH + 4, fmin(bounds.size.height - safe.bottom - halfH - 4, sFloatingBtn.center.y + delta.y));
    sFloatingBtn.center = CGPointMake(nx, ny);
    if (pan.state == UIGestureRecognizerStateEnded) {
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        [ud setFloat:(float)nx forKey:kPrefPosX];
        [ud setFloat:(float)ny forKey:kPrefPosY];
    }
}
@end

@implementation KTImGuiOverlay

+ (void)showInWindow:(UIWindow *)hostWindow
           serverURL:(NSString *)serverURL
          licenseKey:(NSString *)licenseKey
            deviceID:(NSString *)deviceID
           expiresAt:(double)expiresAt
           getKeyURL:(NSString *)getKeyURL {
    ktbridge::InstallDyldMonitor();

    dispatch_async(dispatch_get_main_queue(), ^{
        if (!hostWindow) return;

        if (!sOverlayWindow) {
            if (@available(iOS 13.0, *)) {
                if (hostWindow.windowScene) {
                    sOverlayWindow = [[KTOverlayWindow alloc] initWithWindowScene:hostWindow.windowScene];
                }
            }
            if (!sOverlayWindow) {
                sOverlayWindow = [[KTOverlayWindow alloc] initWithFrame:hostWindow.bounds];
            }
            sOverlayWindow.backgroundColor = [UIColor clearColor];
            sOverlayWindow.windowLevel = UIWindowLevelAlert + 10;
            sOverlayWindow.rootViewController = [UIViewController new];
            sOverlayWindow.rootViewController.view.backgroundColor = [UIColor clearColor];

            sCaptureWrapper = [[KTHideCaptureWrapper alloc] initWithFrame:sOverlayWindow.bounds];
            [sOverlayWindow.rootViewController.view addSubview:sCaptureWrapper];

            sCanvas = [[KTImGuiCanvasView alloc] initWithFrame:sCaptureWrapper.bounds];
            [sCaptureWrapper.protectedContainer addSubview:sCanvas];
            [sCaptureWrapper setCaptureHidden:sCanvas.streamProofEnabled];

            sCanvas.onStreamProofToggled = ^(BOOL enabled) {
                [sCaptureWrapper setCaptureHidden:enabled];
                if (sFloatingBtn) [sCaptureWrapper.protectedContainer bringSubviewToFront:sFloatingBtn];
            };

            sFloatingBtn = [UIButton buttonWithType:UIButtonTypeCustom];
            sFloatingBtn.frame = CGRectMake(24, 140, 48, 48);
            sFloatingBtn.layer.cornerRadius = 24;
            sFloatingBtn.backgroundColor = [UIColor colorWithRed:0.10 green:0.13 blue:0.24 alpha:0.92];
            sFloatingBtn.layer.borderWidth = 1.5;
            sFloatingBtn.layer.borderColor = [UIColor colorWithRed:0.39 green:0.40 blue:0.95 alpha:0.9].CGColor;
            [sFloatingBtn setTitle:@"KT" forState:UIControlStateNormal];
            sFloatingBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
            [sFloatingBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            if ([ud objectForKey:kPrefPosX] && [ud objectForKey:kPrefPosY]) {
                sFloatingBtn.center = CGPointMake([ud floatForKey:kPrefPosX], [ud floatForKey:kPrefPosY]);
            }
            [sFloatingBtn addTarget:[KTImGuiDragHelper class] action:@selector(onTapFloating:) forControlEvents:UIControlEventTouchUpInside];
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[KTImGuiDragHelper class] action:@selector(onPanFloating:)];
            [sFloatingBtn addGestureRecognizer:pan];
            [sCaptureWrapper.protectedContainer addSubview:sFloatingBtn];

            sOverlayWindow.canvasView = sCanvas;
            sOverlayWindow.floatingButton = sFloatingBtn;

            if (!sBgObserver) {
                sBgObserver = [[NSNotificationCenter defaultCenter]
                    addObserverForName:UIApplicationDidEnterBackgroundNotification
                                object:nil
                                 queue:[NSOperationQueue mainQueue]
                            usingBlock:^(__unused NSNotification *note) {
                                [sCanvas setEnteredBackground:YES];
                            }];
            }
            if (!sFgObserver) {
                sFgObserver = [[NSNotificationCenter defaultCenter]
                    addObserverForName:UIApplicationDidBecomeActiveNotification
                                object:nil
                                 queue:[NSOperationQueue mainQueue]
                            usingBlock:^(__unused NSNotification *note) {
                                [sCanvas setEnteredBackground:NO];
                            }];
            }
        } else if (@available(iOS 13.0, *)) {
            if (hostWindow.windowScene && sOverlayWindow.windowScene != hostWindow.windowScene) {
                sOverlayWindow.windowScene = hostWindow.windowScene;
            }
        }

        sCanvas.serverURL = serverURL ?: @"";
        sCanvas.licenseKey = licenseKey ?: @"";
        sCanvas.deviceID = deviceID ?: @"";
        sCanvas.expiresAt = expiresAt;
        sCanvas.getKeyURL = getKeyURL;
        sOverlayWindow.hidden = NO;
    });
}

+ (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (sCanvas) {
            sCanvas.menuOpen = NO;
            sCanvas.showQuickPills = NO;
        }
        if (sOverlayWindow) {
            sOverlayWindow.hidden = YES;
        }
    });
}

+ (BOOL)isVisible {
    return sOverlayWindow != nil && !sOverlayWindow.hidden;
}

@end

#else

@implementation KTImGuiOverlay

#if __has_include(<UIKit/UIKit.h>)
+ (void)showInWindow:(UIWindow *)hostWindow
           serverURL:(NSString *)serverURL
          licenseKey:(NSString *)licenseKey
            deviceID:(NSString *)deviceID
           expiresAt:(double)expiresAt
           getKeyURL:(NSString *)getKeyURL {
    ktbridge::InstallDyldMonitor();
}
#endif

+ (void)hide {}
+ (BOOL)isVisible { return NO; }

@end

#endif
