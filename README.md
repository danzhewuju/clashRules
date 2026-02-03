# Clash Rules 覆写脚本

这是一个用于 Clash/Mihomo 的配置覆写脚本，能够根据订阅节点自动生成代理组、分流规则和 DNS 配置。

## 功能特性

- 自动识别节点所属国家/地区，生成对应的代理组
- 智能识别低倍率节点、落地节点
- 丰富的分流规则（广告拦截、流媒体、AI 服务等）
- 可配置的 DNS 和嗅探功能
- 支持负载均衡或自动测速模式

## 使用方法

在 Clash 客户端（如 Stash、Clash Verge、ClashX Pro 等）的订阅配置中添加覆写脚本。

### 基础用法

```
https://your-subscription-url#script=https://raw.githubusercontent.com/your-repo/clash_rules.js
```

### 带参数用法

通过 URL 参数启用或禁用功能：

```
https://your-subscription-url#script=https://raw.githubusercontent.com/your-repo/clash_rules.js?loadbalance=true&dns=true&threshold=3
```

## 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `loadbalance` | boolean | `false` | 启用负载均衡模式（否则使用延迟测试模式） |
| `landing` | boolean | `false` | 启用落地节点分组（家宽、商宽、星链等） |
| `ipv6` | boolean | `false` | 启用 IPv6 支持 |
| `full` | boolean | `false` | 输出完整配置（包含端口、模式等基础设置） |
| `keepalive` | boolean | `false` | 启用 Keep-Alive 连接保持 |
| `fakeip` | boolean | `false` | 使用 Fake-IP 模式（否则使用 redir-host） |
| `quic` | boolean | `false` | 允许 QUIC 协议（否则拦截 UDP 443 端口） |
| `dns` | boolean | `false` | 启用自定义 DNS 配置 |
| `sniff` | boolean | `false` | 启用协议嗅探 |
| `threshold` | number | `0` | 国家节点分组的最小节点数阈值 |

### 参数示例

```
# 启用负载均衡 + DNS + 嗅探
?loadbalance=true&dns=true&sniff=true

# 启用落地节点 + 完整配置 + Fake-IP
?landing=true&full=true&fakeip=true&dns=true

# 只显示节点数 >= 5 的国家分组
?threshold=5
```

## 代理组说明

### 核心代理组

| 名称 | 类型 | 说明 |
|------|------|------|
| 选择代理 | select | 主代理组，用于手动选择出口策略 |
| 手动选择 | select | 包含所有节点，手动选择单个节点 |
| 故障转移 | fallback | 自动切换可用节点 |
| 直连 | select | 直接连接或走代理 |
| 高优先级 | select | 高优先级流量使用的代理组 |

### 条件代理组

| 名称 | 条件 | 说明 |
|------|------|------|
| 落地节点 | `landing=true` | 家宽、商宽、星链等落地节点 |
| 前置代理 | `landing=true` | 用于落地节点的前置代理选择 |
| 低倍率节点 | 自动检测 | 0.1-0.5 倍率或标记为低倍率的节点 |

### 国家/地区代理组

脚本会自动识别以下国家/地区的节点并创建对应分组：

- 香港、澳门、台湾
- 新加坡、日本、韩国
- 美国、加拿大、英国
- 澳大利亚、德国、法国
- 俄罗斯、泰国、印度、马来西亚

## 分流规则

### 服务分流

| 规则组 | 说明 |
|--------|------|
| AI | ChatGPT、Claude、Gemini 等 AI 服务 |
| Google | Google 全系服务 |
| YouTube | YouTube 视频 |
| Microsoft | Microsoft 服务（国内域名直连） |
| Telegram | Telegram 即时通讯 |
| Netflix | Netflix 流媒体 |
| Spotify | Spotify 音乐 |
| TikTok | TikTok 短视频 |
| Bilibili | B站（优先港台节点解锁） |
| Bahamut | 巴哈姆特动画疯（优先台湾节点） |
| Truth Social | Truth Social（优先美国节点） |
| OneDrive | OneDrive 网盘 |
| PikPak | PikPak 网盘 |
| Crypto | 加密货币相关服务 |
| E-Hentai | E-Hentai |

### 功能分流

| 规则组 | 说明 |
|--------|------|
| 广告拦截 | 广告域名拦截（支持 REJECT / REJECT-DROP） |
| 搜狗输入法 | 搜狗输入法隐私数据（默认直连或拦截） |
| 静态资源 | CDN 静态资源 |
| SSH(22端口) | SSH 连接 |

### 规则优先级

1. 用户自定义规则
2. QUIC 拦截规则（如未启用 `quic`）
3. 广告拦截规则
4. 服务分流规则
5. GFW 规则 → 选择代理
6. 中国大陆规则 → 直连
7. 兜底规则 → 选择代理

## 自定义规则

在 `userDefinedRules` 数组中添加自定义规则，这些规则会被插入到所有规则的最前面：

```javascript
const userDefinedRules = [
  `DOMAIN-SUFFIX,linux.do,${PROXY_GROUPS.HIGH_PRIORITY}`,
  `DOMAIN-SUFFIX,example.com,${PROXY_GROUPS.SELECT}`,
  // 添加更多规则...
];
```

## DNS 配置

启用 `dns=true` 后，脚本会注入以下 DNS 配置：

### redir-host 模式（默认）

- 默认 DNS：`119.29.29.29`、`223.5.5.5`
- 国内 DNS：`system`、`223.5.5.5`、`119.29.29.29`、`180.184.1.1`
- 回退 DNS：`dns0.eu`、`Cloudflare`、`DNS.SB` 等

### Fake-IP 模式（`fakeip=true`）

在 redir-host 基础上启用 Fake-IP，并排除以下域名：
- 私有网络、连通性检测、中国大陆域名
- 米家设备、QQ 登录、iCloud、STUN 服务

## 完整配置模式

启用 `full=true` 会输出完整的 Clash 配置，包含：

```yaml
mixed-port: 7890
redir-port: 7892
tproxy-port: 7893
routing-mark: 7894
allow-lan: true
mode: rule
unified-delay: true
tcp-concurrent: true
find-process-mode: off
log-level: info
external-controller: :9999
```

## 规则提供者

脚本使用以下外部规则集：

| 名称 | 来源 | 更新间隔 |
|------|------|----------|
| ADBlock | adrules.top | 24小时 |
| SogouInput | ruleset.skk.moe | 24小时 |
| StaticResources | ruleset.skk.moe | 24小时 |
| TikTok | powerfullz/override-rules | 24小时 |
| EHentai | powerfullz/override-rules | 24小时 |
| Crypto | powerfullz/override-rules | 24小时 |

## GeoData 数据源

使用 Loyalsoldier 维护的增强版 GeoData：

- geoip.dat / geosite.dat
- Country.mmdb
- GeoLite2-ASN.mmdb

## 注意事项

1. **QUIC 拦截**：默认拦截 UDP 443 端口以强制使用 TCP，如需使用 QUIC 请添加 `quic=true`
2. **节点阈值**：使用 `threshold` 参数可以过滤节点数较少的国家分组
3. **落地节点**：启用 `landing=true` 会将家宽/商宽节点单独分组，适合需要解锁流媒体的场景
4. **低倍率节点**：脚本会自动识别名称中包含 `0.1-0.5`、`低倍率`、`省流`、`大流量`、`实验性` 的节点

## License

MIT
