/*
 * Chingtsi WAF - 离线 IP 属地查询
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 数据源：ip2region 离线库（Apache-2.0，https://github.com/lionsoul2014/ip2region）
 * 格式：8 字节文件头 + 索引区（每项 12 字节）+ 数据区
 *   - 文件头第 0/4 字节：索引区起止偏移（小端 uint32）
 *   - 索引项：startIp / endIp（各 4 字节，按小端存放）+ dataPos（4 字节小端，
 *     高 8 位为记录长度，低 24 位为数据区偏移）
 *   - 数据区记录：4 字节城市 ID + 长度减 4 的 UTF-8 文本，形如
 *     国家|区域|省份|城市|ISP，字段为 "0" 表示无该级信息
 *
 * 本类只做本地只读查询：不联网、不写盘、不参与 WAF 判定，
 * 查询失败时统一返回 "未知"，绝不影响控制台与防护主流程。
 */
package com.chingtsi.waf.geo;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** 离线 IP 属地查询（线程安全，按 IP 结果缓存）。 */
public final class IpLocator {

    private static final int INDEX_BLOCK = 12;
    private static final int CACHE_LIMIT = 20000;

    private static volatile IpLocator instance;

    private final MappedByteBuffer db;
    private final int firstIndex;
    private final int totalBlocks;
    private final String source;
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    private IpLocator(Path file) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r");
             FileChannel ch = raf.getChannel()) {
            long size = ch.size();
            if (size < 32) {
                throw new IOException("地理库文件过小：" + size + " 字节");
            }
            this.db = ch.map(FileChannel.MapMode.READ_ONLY, 0, size);
        }
        // ip2region v1 库全部采用小端序存储，必须先切换字节序再解析头部与索引
        this.db.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        this.firstIndex = db.getInt(0);
        int lastIndex = db.getInt(4);
        if (firstIndex < 0 || lastIndex <= firstIndex || lastIndex > db.capacity()) {
            throw new IOException("地理库索引区异常");
        }
        this.totalBlocks = (lastIndex - firstIndex) / INDEX_BLOCK + 1;
        this.source = file.toString();
    }

    /** 初始化（幂等）：优先命令行 -Dwaf.geodb，其次程序目录 data/ip2region.db。 */
    public static synchronized void init(Path home) {
        if (instance != null) {
            return;
        }
        List<Path> candidates = new ArrayList<>();
        String prop = System.getProperty("waf.geodb");
        if (prop != null && !prop.isBlank()) {
            candidates.add(Path.of(prop));
        }
        if (home != null) {
            candidates.add(home.resolve("data").resolve("ip2region.db"));
            candidates.add(home.resolve("app").resolve("data").resolve("ip2region.db"));
        }
        for (Path p : candidates) {
            if (p == null || !Files.isReadable(p)) {
                continue;
            }
            try {
                instance = new IpLocator(p);
                return;
            } catch (IOException | RuntimeException ignored) {
                // 尝试下一个候选路径
            }
        }
    }

    public static boolean ready() {
        return instance != null;
    }

    /** 地理库状态描述，供控制台“防护配置”页展示。 */
    public static String status() {
        IpLocator l = instance;
        if (l == null) {
            return "未加载（缺少 data\\ip2region.db）";
        }
        return l.source + "（索引 " + l.totalBlocks + " 条）";
    }

    /** 归属地短名，如“浙江 杭州”“美国 圣何塞”“内网”。 */
    public static String area(String ip) {
        return format(ip, false);
    }

    /** 归属地完整信息，如“中国 · 浙江省 · 杭州市 · 阿里云”。 */
    public static String detail(String ip) {
        return format(ip, true);
    }

    private static String format(String ip, boolean full) {
        String v4 = normalize(ip);
        if (v4 == null) {
            return "未知";
        }
        String scope = privateScope(v4);
        if (scope != null) {
            return scope;
        }
        IpLocator l = instance;
        if (l == null) {
            return "-";
        }
        String raw = l.lookup(v4);
        if (raw == null || raw.isBlank()) {
            return "未知";
        }
        String[] f = raw.split("\\|", -1);
        String country = field(f, 0);
        String region = field(f, 1);
        String province = field(f, 2);
        String city = field(f, 3);
        String isp = field(f, 4);
        if ("内网IP".equals(country) || "内网IP".equals(isp)) {
            return "内网";
        }
        if (full) {
            StringBuilder sb = new StringBuilder();
            for (String part : new String[]{country, region, province, city, isp}) {
                if (!part.isEmpty()) {
                    if (sb.length() > 0) {
                        sb.append(" · ");
                    }
                    sb.append(part);
                }
            }
            return sb.length() == 0 ? "未知" : sb.toString();
        }
        String prov = shortName(province);
        String c = shortName(city);
        if ("中国".equals(country) || "China".equalsIgnoreCase(country)) {
            if (!prov.isEmpty() && !c.isEmpty()) {
                return prov + " " + c;
            }
            if (!prov.isEmpty()) {
                return prov;
            }
            return c.isEmpty() ? "中国" : c;
        }
        if (country.isEmpty()) {
            return prov.isEmpty() ? (c.isEmpty() ? "未知" : c) : prov;
        }
        if (!c.isEmpty() && !"0".equals(c)) {
            return country + " " + c;
        }
        return country;
    }

    private static String field(String[] f, int i) {
        if (i >= f.length) {
            return "";
        }
        String v = f[i].strip();
        return "0".equals(v) ? "" : v;
    }

    /** 省级/市级简称：去掉“省/市/自治区/特别行政区”等后缀。 */
    private static String shortName(String s) {
        if (s == null || s.isEmpty() || "0".equals(s)) {
            return "";
        }
        String v = s.strip();
        switch (v) {
            case "内蒙古自治区": return "内蒙古";
            case "广西壮族自治区": return "广西";
            case "西藏自治区": return "西藏";
            case "宁夏回族自治区": return "宁夏";
            case "新疆维吾尔自治区": return "新疆";
            case "香港特别行政区": return "香港";
            case "澳门特别行政区": return "澳门";
            default:
                break;
        }
        if (v.endsWith("特别行政区")) {
            return v.substring(0, v.length() - 5);
        }
        if (v.endsWith("自治区")) {
            return v.substring(0, v.length() - 3);
        }
        if (v.endsWith("省") || v.endsWith("市")) {
            return v.substring(0, v.length() - 1);
        }
        return v;
    }

    /** 统一为点分 IPv4（兼容 ::ffff:a.b.c.d）；非 IPv4 返回 null。 */
    private static String normalize(String ip) {
        if (ip == null) {
            return null;
        }
        String s = ip.strip();
        if (s.startsWith("::ffff:")) {
            s = s.substring(7);
        }
        String[] p = s.split("\\.");
        if (p.length != 4) {
            return null;
        }
        for (String seg : p) {
            if (seg.isEmpty() || seg.length() > 3) {
                return null;
            }
            for (int i = 0; i < seg.length(); i++) {
                if (!Character.isDigit(seg.charAt(i))) {
                    return null;
                }
            }
            if (Integer.parseInt(seg) > 255) {
                return null;
            }
        }
        return s;
    }

    /** 本机 / 内网直接返回，不查库。 */
    private static String privateScope(String ip) {
        String[] p = ip.split("\\.");
        int a = Integer.parseInt(p[0]);
        int b = Integer.parseInt(p[1]);
        if (a == 127 || (a == 0 && b == 0)) {
            return "本机";
        }
        if (a == 10 || (a == 192 && b == 168) || (a == 169 && b == 254)) {
            return "内网";
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return "内网";
        }
        return null;
    }

    private String lookup(String ip) {
        String cached = cache.get(ip);
        if (cached != null) {
            return cached.isEmpty() ? null : cached;
        }
        String region = query(ip);
        if (cache.size() > CACHE_LIMIT) {
            cache.clear();
        }
        cache.put(ip, region == null ? "" : region);
        return region;
    }

    private String query(String ip) {
        int target = ipToInt(ip);
        int low = 0;
        int high = totalBlocks - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            int base = firstIndex + mid * INDEX_BLOCK;
            if (base + INDEX_BLOCK > db.capacity()) {
                return null;
            }
            long start = Integer.toUnsignedLong(db.getInt(base));
            long end = Integer.toUnsignedLong(db.getInt(base + 4));
            long t = Integer.toUnsignedLong(target);
            if (t < start) {
                high = mid - 1;
            } else if (t > end) {
                low = mid + 1;
            } else {
                int pos = db.getInt(base + 8);
                int len = (pos >>> 24) & 0xFF;
                int off = pos & 0x00FFFFFF;
                if (len <= 4 || off + len > db.capacity()) {
                    return null;
                }
                byte[] text = new byte[len - 4];
                for (int i = 0; i < text.length; i++) {
                    text[i] = db.get(off + 4 + i);
                }
                return new String(text, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static int ipToInt(String ip) {
        String[] p = ip.split("\\.");
        return (Integer.parseInt(p[0]) << 24)
                | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8)
                | Integer.parseInt(p[3]);
    }

    /** 供命令行自测：java -cp chingtsi-waf.jar com.chingtsi.waf.geo.IpLocator 8.8.8.8 */
    public static void main(String[] args) {
        init(Path.of(".").toAbsolutePath());
        System.out.println("geo: " + status());
        for (String ip : args) {
            System.out.printf(Locale.ROOT, "%-18s %-16s %s%n", ip, area(ip), detail(ip));
        }
    }
}
