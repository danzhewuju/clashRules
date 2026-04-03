const NODE_SUFFIX = "节点";

/**
 * 工具函数：解析布尔值
 */
function parseBool(e) {
  return "boolean" == typeof e ? e : "string" == typeof e && ("true" === e.toLowerCase() || "1" === e);
}

/**
 * 工具函数：解析数字
 */
function parseNumber(e, t = 0) {
  if (null == e) return t;
  const o = parseInt(e, 10);
  return isNaN(o) ? t : o;
}

/**
 * 构建功能开关标识
 */
function buildFeatureFlags(e) {
  const t = Object.entries({
    loadbalance: "loadBalance",
    landing: "landing",
    ipv6: "ipv6Enabled",
    full: "fullConfig",
    keepalive: "keepAliveEnabled",
    fakeip: "fakeIPEnabled",
    quic: "quicEnabled",
    dns: "dnsEnabled",
    sniff: "snifferEnabled"
  }).reduce((t, [o, r]) => (t[r] = parseBool(e[o]) || !1, t), {});
  t.countryThreshold = parseNumber(e.threshold, 0);
  return t;
}

// 初始化参数
const rawArgs = "undefined" != typeof $arguments ? $arguments : {};
const {
  loadBalance,
  landing,
  ipv6Enabled,
  fullConfig,
  keepAliveEnabled,
  fakeIPEnabled,
  quicEnabled,
  dnsEnabled,
  snifferEnabled,
  countryThreshold
} = buildFeatureFlags(rawArgs);

/**
 * 过滤并获取国家节点分组名称
 */
function getCountryGroupNames(e, t) {
  return e.filter(e => e.count >= t).map(e => e.country + "节点");
}

function stripNodeSuffix(e) {
  const t = new RegExp("节点$");
  return e.map(e => e.replace(t, ""));
}

// 代理组常量定义
const PROXY_GROUPS = {
  SELECT: "选择代理",
  MANUAL: "手动选择",
  FALLBACK: "故障转移",
  DIRECT: "直连",
  LANDING: "落地节点",
  LOW_COST: "低倍率节点",
  HIGH_PRIORITY: "高优先级",
  PERSONAL: "自建节点"
};

const PERSONAL_PROXIES = [
  {
    name: "xx",
    type: "vless",
    server: "xxx",
    port: 443,
    uuid: "xxx",
    udp: true,
    tls: true,
    "skip-cert-verify": false,
    flow: "",
    "client-fingerprint": "ios",
    servername: "xxx",
    network: "ws",
    "ws-opts": {
      path: "/xxx",
      headers: {
        Host: "xxx"
      }
    }
  }
];

const buildList = (...e) => e.flat().filter(Boolean);
const getPersonalProxyNames = () => PERSONAL_PROXIES.map(e => e.name);

/**
 * 构建基础代理列表
 */
function buildBaseLists({ landing: e, lowCost: t, countryGroupNames: o, personalProxyNames: r }) {
  const n = buildList(
    PROXY_GROUPS.FALLBACK,
    e && PROXY_GROUPS.LANDING,
    r.length && PROXY_GROUPS.PERSONAL,
    o,
    t && PROXY_GROUPS.LOW_COST,
    PROXY_GROUPS.MANUAL,
    PROXY_GROUPS.HIGH_PRIORITY,
    "DIRECT"
  );
  return {
    defaultProxies: buildList(PROXY_GROUPS.SELECT, r.length && PROXY_GROUPS.PERSONAL, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT, PROXY_GROUPS.HIGH_PRIORITY),
    defaultProxiesDirect: buildList(PROXY_GROUPS.DIRECT, r.length && PROXY_GROUPS.PERSONAL, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL),
    defaultSelector: n,
    defaultFallback: buildList(e && PROXY_GROUPS.LANDING, r.length && PROXY_GROUPS.PERSONAL, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.MANUAL, "DIRECT")
  };
}

// 规则提供者配置
const ruleProviders = {
  ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" },
  SogouInput: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", path: "./ruleset/SogouInput.txt" },
  StaticResources: { type: "http", behavior: "domain", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt", path: "./ruleset/StaticResources.txt" },
  CDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", path: "./ruleset/CDNResources.txt" },
  TikTok: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list", path: "./ruleset/TikTok.list" },
  EHentai: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list", path: "./ruleset/EHentai.list" },
  SteamFix: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list", path: "./ruleset/SteamFix.list" },
  GoogleFCM: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list", path: "./ruleset/FirebaseCloudMessaging.list" },
  AdditionalFilter: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list", path: "./ruleset/AdditionalFilter.list" },
  AdditionalCDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list", path: "./ruleset/AdditionalCDNResources.list" },
  Crypto: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", path: "./ruleset/Crypto.list" }
};

// 用户定义的规则
const userDefinedRules = [
  `DOMAIN-SUFFIX,linux.do,${PROXY_GROUPS.HIGH_PRIORITY}`,
  `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.HIGH_PRIORITY}`,
  `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.HIGH_PRIORITY}`,
  `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.HIGH_PRIORITY}`,
  `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.HIGH_PRIORITY}`,
];

// 基础分流规则
const baseRules = [
  "RULE-SET,ADBlock,广告拦截",
  "RULE-SET,AdditionalFilter,广告拦截",
  "RULE-SET,SogouInput,搜狗输入法",
  "DOMAIN-SUFFIX,truthsocial.com,Truth Social",
  "DOMAIN-SUFFIX,facebook.com,Facebook",
  "RULE-SET,StaticResources,静态资源",
  "RULE-SET,CDNResources,静态资源",
  "RULE-SET,AdditionalCDNResources,静态资源",
  "RULE-SET,Crypto,Crypto",
  "RULE-SET,EHentai,E-Hentai",
  "RULE-SET,TikTok,TikTok",
  `RULE-SET,SteamFix,${PROXY_GROUPS.DIRECT}`,
  `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`,
  `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
  `GEOSITE,GOOGLE-PLAY@CN,${PROXY_GROUPS.DIRECT}`,
  "GEOSITE,ONEDRIVE,OneDrive",
  "GEOSITE,MICROSOFT,Microsoft",
  "GEOSITE,CATEGORY-AI-!CN,AI",
  "GEOSITE,TELEGRAM,Telegram",
  "GEOSITE,YOUTUBE,YouTube",
  "GEOSITE,GOOGLE,Google",
  "GEOSITE,NETFLIX,Netflix",
  "GEOSITE,SPOTIFY,Spotify",
  "GEOSITE,BAHAMUT,Bahamut",
  "GEOSITE,BILIBILI,Bilibili",
  `GEOSITE,MICROSOFT@CN,${PROXY_GROUPS.DIRECT}`,
  "GEOSITE,PIKPAK,PikPak",
  `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`,
  `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
  `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`,
  "GEOIP,NETFLIX,Netflix,no-resolve",
  "GEOIP,TELEGRAM,Telegram,no-resolve",
  `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
  `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
  "DST-PORT,22,SSH(22端口)",
  `MATCH,${PROXY_GROUPS.SELECT}`
];

// 将用户定义的规则插入到baseRules的第0个位置
baseRules.unshift(...userDefinedRules);

function buildRules({ quicEnabled: e }) {
  const t = [...baseRules];
  return e || t.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"), t;
}

// 嗅探配置
const snifferConfig = {
  sniff: {
    TLS: { ports: [443, 8443] },
    HTTP: { ports: [80, 8080, 8880] },
    QUIC: { ports: [443, 8443] }
  },
  "override-destination": !1,
  enable: !0,
  "force-dns-mapping": !0,
  "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"]
};

/**
 * 构建 DNS 配置
 */
function buildDnsConfig({ mode: e, fakeIpFilter: t }) {
  const o = {
    enable: !0,
    ipv6: ipv6Enabled,
    "prefer-h3": !0,
    "enhanced-mode": e,
    "default-nameserver": ["119.29.29.29", "223.5.5.5"],
    nameserver: ["system", "223.5.5.5", "119.29.29.29", "180.184.1.1"],
    fallback: ["quic://dns0.eu", "https://dns.cloudflare.com/dns-query", "https://dns.sb/dns-query", "tcp://208.67.222.222", "tcp://8.26.56.2"],
    "proxy-server-nameserver": ["https://dns.alidns.com/dns-query", "tls://dot.pub"]
  };
  return t && (o["fake-ip-filter"] = t), o;
}

const dnsConfig = buildDnsConfig({ mode: "redir-host" });
const dnsConfigFakeIp = buildDnsConfig({
  mode: "fake-ip",
  fakeIpFilter: ["geosite:private", "geosite:connectivity-check", "geosite:cn", "Mijia Cloud", "dig.io.mi.com", "localhost.ptlogin2.qq.com", "*.icloud.com", "*.stun.*.*", "*.stun.*.*.*"]
});

const geoxURL = {
  geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
  geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
  mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
  asn: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"
};

// 国家/地区元数据映射
const countriesMeta = {
  "香港": { pattern: "香港|港|HK|hk|Hong Kong|HongKong|hongkong|🇭🇰", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png" },
  "澳门": { pattern: "澳门|MO|Macau|🇲🇴", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Macao.png" },
  "台湾": { pattern: "台|新北|彰化|TW|Taiwan|🇹🇼", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png" },
  "新加坡": { pattern: "新加坡|坡|狮城|SG|Singapore|🇸🇬", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png" },
  "日本": { pattern: "日本|川日|东京|大阪|泉日|埼玉|沪日|深日|JP|Japan|🇯🇵", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png" },
  "韩国": { pattern: "KR|Korea|KOR|首尔|韩|韓|🇰🇷", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Korea.png" },
  "美国": { pattern: "美国|美|US|United States|🇺🇸", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png" },
  "加拿大": { pattern: "加拿大|Canada|CA|🇨🇦", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Canada.png" },
  "英国": { pattern: "英国|United Kingdom|UK|伦敦|London|🇬🇧", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_Kingdom.png" },
  "澳大利亚": { pattern: "澳洲|澳大利亚|AU|Australia|🇦🇺", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Australia.png" },
  "德国": { pattern: "德国|德|DE|Germany|🇩🇪", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Germany.png" },
  "法国": { pattern: "法国|法|FR|France|🇫🇷", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/France.png" },
  "俄罗斯": { pattern: "俄罗斯|俄|RU|Russia|🇷🇺", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png" },
  "泰国": { pattern: "泰国|泰|TH|Thailand|🇹🇭", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Thailand.png" },
  "印度": { pattern: "印度|IN|India|🇮🇳", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/India.png" },
  "马来西亚": { pattern: "马来西亚|马来|MY|Malaysia|🇲🇾", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Malaysia.png" }
};

function hasLowCost(e) {
  const t = /0\.[0-5]|低倍率|省流|大流量|实验性/i;
  return (e.proxies || []).some(e => t.test(e.name));
}

/**
 * 解析节点列表，统计各国家节点数量
 */
function parseCountries(e) {
  const t = e.proxies || [],
    o = /家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地/i,
    r = Object.create(null),
    n = {};
  for (const [e, t] of Object.entries(countriesMeta)) n[e] = new RegExp(t.pattern.replace(/^\(\?i\)/, ""));
  for (const e of t) {
    const t = e.name || "";
    if (!o.test(t))
      for (const [e, o] of Object.entries(n))
        if (o.test(t)) {
          r[e] = (r[e] || 0) + 1;
          break;
        }
  }
  const s = [];
  for (const [e, t] of Object.entries(r)) s.push({ country: e, count: t });
  return s;
}

/**
 * 构建国家/地区级别的代理组（负载均衡或延迟测试）
 */
function buildCountryProxyGroups({ countries: e, landing: t, loadBalance: o }) {
  const r = [],
    n = "0\\.[0-5]|低倍率|省流|大流量|实验性",
    s = o ? "load-balance" : "url-test";
  for (const l of e) {
    const e = countriesMeta[l];
    if (!e) continue;
    const i = {
      name: `${l}节点`,
      icon: e.icon,
      "include-all": !0,
      filter: e.pattern,
      "exclude-filter": t ? `(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地|${n}` : n,
      type: s
    };
    o || Object.assign(i, { url: "https://cp.cloudflare.com/generate_204", interval: 60, tolerance: 20, lazy: !1 }),
    r.push(i);
  }
  return r;
}

/**
 * 构建完整的代理组结构
 */
function buildProxyGroups({ landing: e, countries: t, countryProxyGroups: o, lowCost: r, defaultProxies: n, defaultProxiesDirect: s, defaultSelector: l, defaultFallback: i, personalProxyNames: a }) {
  const h = t.includes("台湾"),
    c = t.includes("香港"),
    p = t.includes("美国"),
    u = e ? l.filter(e => e !== PROXY_GROUPS.LANDING && e !== PROXY_GROUPS.FALLBACK) : [];
    
  return [
    { name: PROXY_GROUPS.SELECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png", type: "select", proxies: l },
    { name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": !0, type: "select" },
    a.length ? { name: PROXY_GROUPS.PERSONAL, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png", type: "select", proxies: a } : null,
    e ? { name: "前置代理", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png", type: "select", "include-all": !0, "exclude-filter": "(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地", proxies: u } : null,
    e ? { name: PROXY_GROUPS.LANDING, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png", type: "select", "include-all": !0, filter: "(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地" } : null,
    // 避免策略组自引用导致 ProxyGroup loop
    {
      name: PROXY_GROUPS.HIGH_PRIORITY,
      icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/v2tun.png",
      type: "select",
      proxies: buildList(
        a.length && PROXY_GROUPS.PERSONAL,
        n.filter(e => e !== PROXY_GROUPS.HIGH_PRIORITY && e !== PROXY_GROUPS.SELECT && e !== PROXY_GROUPS.DIRECT && e !== PROXY_GROUPS.PERSONAL)
      )
    },
    { name: PROXY_GROUPS.FALLBACK, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bypass.png", type: "fallback", url: "https://cp.cloudflare.com/generate_204", proxies: i, interval: 180, tolerance: 20, lazy: !1 },
    { name: "静态资源", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cloudflare.png", type: "select", proxies: n },
    { name: "AI", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/chatgpt.png", type: "select", proxies: n },
    { name: "Crypto", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cryptocurrency_3.png", type: "select", proxies: n },
    { name: "Facebook", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Facebook.png", type: "select", proxies: n },
    { name: "Google", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Google.png", type: "select", proxies: n },
    { name: "Microsoft", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Microsoft_Copilot.png", type: "select", proxies: n },
    { name: "YouTube", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png", type: "select", proxies: n },
    { name: "Bilibili", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png", type: "select", proxies: h && c ? [PROXY_GROUPS.DIRECT, "台湾节点", "香港节点"] : s },
    { name: "Bahamut", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bahamut.png", type: "select", proxies: h ? ["台湾节点", PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT] : n },
    { name: "Netflix", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png", type: "select", proxies: n },
    { name: "TikTok", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/TikTok.png", type: "select", proxies: n },
    { name: "Spotify", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Spotify.png", type: "select", proxies: n },
    { name: "E-Hentai", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Ehentai.png", type: "select", proxies: n },
    { name: "Telegram", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png", type: "select", proxies: n },
    { name: "Truth Social", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/TruthSocial.png", type: "select", proxies: p ? ["美国节点", PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL] : n },
    { name: "OneDrive", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Onedrive.png", type: "select", proxies: n },
    { name: "PikPak", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/PikPak.png", type: "select", proxies: n },
    { name: "SSH(22端口)", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Server.png", type: "select", proxies: n },
    { name: "搜狗输入法", icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Sougou.png", type: "select", proxies: [PROXY_GROUPS.DIRECT, "REJECT"] },
    { name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] },
    { name: "广告拦截", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png", type: "select", proxies: ["REJECT", "REJECT-DROP", PROXY_GROUPS.DIRECT] },
    r ? { name: PROXY_GROUPS.LOW_COST, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Lab.png", type: "url-test", url: "https://cp.cloudflare.com/generate_204", "include-all": !0, filter: "(?i)0.[0-5]|低倍率|省流|大流量|实验性" } : null,
    ...o
  ].filter(Boolean);
}

/**
 * 主入口函数
 */
function main(e) {
  const t = { proxies: [...PERSONAL_PROXIES, ...(e.proxies || [])] },
    r = getPersonalProxyNames(),
    o = parseCountries(t),
    n = hasLowCost(t),
    s = getCountryGroupNames(o, countryThreshold),
    l = stripNodeSuffix(s),
    { defaultProxies: i, defaultProxiesDirect: a, defaultSelector: c, defaultFallback: p } = buildBaseLists({ landing: landing, lowCost: n, countryGroupNames: s, personalProxyNames: r }),
    u = buildCountryProxyGroups({ countries: l, landing: landing, loadBalance: loadBalance }),
    d = buildProxyGroups({ landing: landing, countries: l, countryProxyGroups: u, lowCost: n, defaultProxies: i, defaultProxiesDirect: a, defaultSelector: c, defaultFallback: p, personalProxyNames: r }),
    g = d.map(e => e.name);
    
  // 添加全局选择组
  d.push({ name: "GLOBAL", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png", "include-all": !0, type: "select", proxies: g });
  
  const y = buildRules({ quicEnabled: quicEnabled });
  
  // 完整配置注入
  return fullConfig && Object.assign(t, {
    "mixed-port": 7890,
    "redir-port": 7892,
    "tproxy-port": 7893,
    "routing-mark": 7894,
    "allow-lan": !0,
    ipv6: ipv6Enabled,
    mode: "rule",
    "unified-delay": !0,
    "tcp-concurrent": !0,
    "find-process-mode": "off",
    "log-level": "info",
    "geodata-loader": "standard",
    "external-controller": ":9999",
    "disable-keep-alive": !keepAliveEnabled,
    profile: { "store-selected": !0 }
  }),
  Object.assign(t, {
    "proxy-groups": d,
    "rule-providers": ruleProviders,
    rules: y,
    ...(snifferEnabled ? { sniffer: snifferConfig } : {}),
    ...(dnsEnabled ? { dns: fakeIPEnabled ? dnsConfigFakeIp : dnsConfig } : {}),
    "geodata-mode": !0,
    "geox-url": geoxURL
  }),
  t;
}