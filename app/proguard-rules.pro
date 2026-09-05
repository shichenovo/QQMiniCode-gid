# ============================================================
# R8 / ProGuard 混淆规则 —— QQ小程序抓包
# 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2
#
# 目标：防静态反编译 + AI 辅助逆向（提高分析成本）。
# 原则：除系统/框架要求保留的类外，全部混淆。
# ============================================================

# ---------- 保留注解属性 ----------
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature, Exceptions

# ---------- Manifest 声明的组件（Android 按名称实例化，禁止改名/裁剪） ----------
# launcher：Android 按名称实例化，禁止改名
-keep class com.example.qqminicodecapture.ui.MainActivity { *; }
-keep class com.example.qqminicodecapture.vpn.CaptureVpnService { *; }

# ---------- BouncyCastle（Provider SPI：按算法名反射注册，禁止混淆/裁剪/优化） ----------
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
-dontwarn javax.security.auth.**

# ---------- 各进程独立初始化入口（多进程场景下静态单例必须保留类结构） ----------
# :vpn 进程入口是 CaptureVpnService，其直接/间接引用的类交给 R8 调用链保留即可；
# 不额外 keep 具体业务类（它们正是要被混淆的对象）。

# ---------- 关闭无意义的 "无法访问" 提示 ----------
-dontwarn java.awt.**
-dontwarn javax.swing.**
