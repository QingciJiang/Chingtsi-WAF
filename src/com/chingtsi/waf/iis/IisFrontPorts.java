/*
 * Chingtsi WAF - 防护端口规划
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 把「IIS 站点端口」映射到「WAF 前置监听端口」。
 * <p>IIS 自身已占用站点端口，WAF 无法直接复用，因此为每个站点端口派生一个前置端口：</p>
 * <ol>
 *   <li>配置项 {@code iis.front.map} 显式指定，例如 {@code 80:8091,8080:16080}；</li>
 *   <li>未显式指定时：端口号最小的站点端口沿用 {@code listen.port}（保持 Cloudflare 隧道指向不变），
 *       其余端口取 {@code 站点端口 + 8000}，冲突则继续 +1000；</li>
 *   <li>任何情况下前置端口都不会等于 IIS 站点端口，避免与 IIS 抢端口。</li>
 * </ol>
 */
public final class IisFrontPorts {

    private IisFrontPorts() {
    }

    /**
     * @param sitePorts IIS 站点 HTTP 端口（已去重升序）
     * @param listenPort 配置里的 listen.port，用于第一个站点端口
     * @param explicit   配置里 iis.front.map 的原始文本，可为空
     * @return IIS 端口 → WAF 前置端口（有序）
     */
    public static Map<Integer, Integer> plan(List<Integer> sitePorts, int listenPort, String explicit) {
        Map<Integer, Integer> map = new LinkedHashMap<>();
        if (sitePorts == null || sitePorts.isEmpty()) {
            return map;
        }
        Map<Integer, Integer> declared = parseMap(explicit);
        Set<Integer> used = new LinkedHashSet<>(sitePorts);

        List<Integer> ports = new ArrayList<>(sitePorts);
        ports.sort(Integer::compareTo);

        for (int i = 0; i < ports.size(); i++) {
            int sitePort = ports.get(i);
            Integer fixed = declared.get(sitePort);
            if (fixed != null && fixed > 0 && fixed <= 65535 && !used.contains(fixed)) {
                map.put(sitePort, fixed);
                used.add(fixed);
                continue;
            }
            if (i == 0 && listenPort > 0 && listenPort <= 65535
                    && !used.contains(listenPort) && !containsValue(map, listenPort)) {
                map.put(sitePort, listenPort);
                used.add(listenPort);
                continue;
            }
            int front = sitePort + 8000;
            while (front > 65535 || used.contains(front)) {
                front += 1000;
            }
            map.put(sitePort, front);
            used.add(front);
        }
        return map;
    }

    /** 解析 "80:8091, 8080:16080" 形式的映射表。 */
    public static Map<Integer, Integer> parseMap(String text) {
        Map<Integer, Integer> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) {
            return map;
        }
        for (String part : text.split("[,;\\s]+")) {
            String t = part.trim();
            if (t.isEmpty() || !t.contains(":")) {
                continue;
            }
            String[] kv = t.split(":", 2);
            try {
                int k = Integer.parseInt(kv[0].trim());
                int v = Integer.parseInt(kv[1].trim());
                if (k > 0 && v > 0) {
                    map.put(k, v);
                }
            } catch (NumberFormatException ignored) {
                // 忽略非法项
            }
        }
        return map;
    }

    /** 反向查询：前置端口 → IIS 端口。 */
    public static int sitePortOf(Map<Integer, Integer> plan, int frontPort) {
        for (Map.Entry<Integer, Integer> e : plan.entrySet()) {
            if (e.getValue() == frontPort) {
                return e.getKey();
            }
        }
        return 0;
    }

    /** 便于界面展示：80→8091, 8080→16080 */
    public static String describe(Map<Integer, Integer> plan) {
        if (plan.isEmpty()) {
            return "无";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, Integer> e : plan.entrySet()) {
            if (sb.length() > 0) {
                sb.append("，");
            }
            sb.append(e.getKey()).append(" → ").append(e.getValue());
        }
        return sb.toString();
    }

    private static boolean containsValue(Map<Integer, Integer> map, int v) {
        return map.containsValue(v);
    }

    static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
