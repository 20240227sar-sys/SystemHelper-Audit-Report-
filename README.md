# SystemHelper-Audit-Report-
逆向分析 國產Android联通预装 SystemHelper 组件及无 Root 防御指南

移动端逆向实录：运营商特权组件 SystemHelper 深度剖析与绞杀

目标组件：com.mobiletools.systemhelper
测试环境：OPPO ColorOS (Android 12/13)，无 Root 权限 (仅 Shell UID 2000)
审计工具：Termux, MT管理器 (Dex编辑器++), Jadx, keytool

一、 目标锁定与身份确认

该组件并非普通流氓软件，而是固化在 OPPO 系统特权分区的中国联通 OMA-DM 遥测插件。

1. 物理路径与版本信息

使用 Shell 权限直接查询系统包管理器的底层信息：

```bash
# 查询包的物理路径、版本号及标志位
dumpsys package com.mobiletools.systemhelper | grep -E 'codePath|versionName|pkgFlags'

# 输出结果：
# codePath=/my_bigball/priv-app/SystemHelper-Oppo-20230301  (OPPO特权分区)
# versionName=1.2-20230301
# pkgFlags=[ SYSTEM HAS CODE ALLOW_CLEAR_USER_DATA ]
```

2. 极其拉胯的通信加密（1024-bit RSA）

将 APK 解包后，提取 assets/pub.cer 证书。这是用于 SSL Pinning 防抓包的，但强度令人啼笑皆非：

```bash
# 解析证书信息
keytool -printcert -file assets/pub.cer

# 输出关键信息：
# Owner: CN=UNICOM, OU=UNICOM, O=UNICOM, L=BJ, ST=BJ, C=CN  (联通自签名)
# Valid from: 2019 until: 2119 (有效期100年，极其敷衍)
# Subject Public Key Algorithm: 1024-bit RSA key (weak) (早已被淘汰的弱加密)
```

3. 硬编码的明文上报接口

通过 MT 管理器搜索 http://，在 f0/f.smali 中抓取到联通服务器的明文地址：

```smali
# 将真实的接口地址替换为本地地址，用于劫持流量
.field public static w:Ljava/lang/String; = "http://127.0.0.1:9999/registerv3"
.field public static x:Ljava/lang/String; = "http://127.0.0.1:9999/public/ip"
```

二、 越界权限与行为审计

1. 令人发指的特权列表

通过 dumpsys package 抓取其申请的核心权限（普通应用根本无法获取）：

```text
READ_PRIVILEGED_PHONE_STATE  # 核心特权！强行读取双卡 IMEI, IMSI, ICCID
ACCESS_BACKGROUND_LOCATION   # 默认授予！APP关闭也能在后台静默定位
PACKAGE_USAGE_STATS          # 监控用户每天玩什么APP、玩了多久
QUERY_ALL_PACKAGES           # 读取手机里安装的所有软件列表
SCHEDULE_EXACT_ALARM         # 精确闹钟，用于定时唤醒上报
```

2. 定时唤醒机制（诈尸）

通过 dumpsys alarm 抓取它的唤醒任务：

```bash
dumpsys alarm | grep -i systemhelper

# 输出结果：
# *walarm*:com.mobiletools.systemhelper/.control.ScheduleRegisterReceiver (约20小时唤醒一次)
# *walarm*:com.mobiletools.systemhelper/.control.SIMStateReceiver (插拔SIM卡或断网时触发)
```

三、 源码级反编译分析 (Jadx)

1. 反射穿透与双卡收割

在 e0/r.java 和 e0/e0.java 中，发现它利用 Java 反射 (setAccessible(true)) 强行穿透 Android 高版本的隐私限制：

```java
// 强行读取卡槽 0 和卡槽 1 的 IMEI
gVar.f1583g = telephonyManager.getImei(0);
gVar.f1594r = telephonyManager.getImei(1);

// 读取 IMSI (手机号识别码) 和 ICCID (SIM卡序列号)
gVar.f1585i = telephonyManagerCreateForSubscriptionId.getSubscriberId();
gVar.f1584h = telephonyManagerCreateForSubscriptionId.getSimSerialNumber();
```

2. 庞大的 OEM 适配字典

为了让各家手机厂商的特权接口都能用，代码中硬编码了极其庞大的机型字典（y1.java）：

```java
f1666a.put("PDNM00", "OPPO");     // OPPO 某机型
f1666a.put("HLTE226T", "Hisense");// 海信某机型
```

四、 动态魔改与逆向对抗 (Smali注入)

为了抓取它上报的数据，我们尝试在 Smali 层面进行重打包脱敏。

1. 污染隐私数据防崩溃

在 e0/e0.smali 中找到 getImei 的反射调用，在系统返回结果后，立刻用假数据覆盖寄存器 v9：

```smali
invoke-static {v9, v3, v12}, Lf0/o;->c(...)Ljava/lang/Object; # 执行反射获取真实IMEI
move-result-object v9
const-string v9, "FAKE_IMEI_88888888" # 强行注入假数据，防止上报时暴露真实串号
```

2. 绕过签名冲突 (AndroidManifest.xml)

系统不允许安装签名不一致的同名应用。我们通过修改清单文件实现“狸猫换太子”：

```xml
<!-- 删掉共享UID，取消与系统底层的特权绑定 -->
<!-- <android:sharedUserId="com.mobiletools.systemhelper.uid" /> -->

<!-- 修改包名，系统会认为这是一个全新的普通应用 -->
<manifest ... package="com.mobiletools.systemhelper.fake">
```

3. 尝试夺舍 UI 失败 (TestActivity.smali)

我们试图把它的测试界面改成“启动浏览器”，直接向本地 9999 端口发包测试：

```smali
# 伪造一个打开浏览器的 Intent
new-instance v0, Landroid/content/Intent;
const-string v1, "android.intent.action.VIEW"
invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
const-string v1, "http://127.0.0.1:9999/test_from_smali"
invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
move-result-object v1
invoke-virtual {v0, v1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;
invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
return-void
```

⚠️ 实测血泪教训：
由于该组件具备强烈的 Native 层防篡改校验 (SO库) 以及 签名校验，在剥夺其 priv-app 特权并重签名后，一旦试图拉起服务或UI，会立刻触发底层的 System.exit() 静默自杀。连 Java 层的 FATAL EXCEPTION 都不留。这证明了它完全是一个依赖特权作恶的寄生虫，一旦失去特权环境，自身逻辑立刻崩溃。

五、 终极处置方案（免 Root 防御）

既然我们无法在保留其运行的情况下抓包，最安全的方式就是彻底切断它的运行。

1. 剥离与卸载（推荐，安全可逆）

```bash
# 从当前用户空间彻底移除（不破坏系统分区，不影响系统OTA）
pm uninstall -k --user 0 com.mobiletools.systemhelper
```

2. 冻结封印（不想卸载时的折中方案）

```bash
# 仅停用，保留应用数据
pm disable-user --user 0 com.mobiletools.systemhelper
```

3. ⚠️ 避坑警告

切勿删除 com.qualcomm.qti.services.systemhelper！
这是高通芯片的底层系统服务，名字很像，但误删会导致指纹、基带或电源管理异常。清理时请认准前缀 com.mobiletools.
