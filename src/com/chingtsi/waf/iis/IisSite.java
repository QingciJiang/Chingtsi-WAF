/*
 * Chingtsi WAF - IIS 站点
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * IIS 上的一个网站。
 *
 * @param id           站点 ID
 * @param name         站点名称
 * @param state        运行状态（Started / Stopped / Unknown）
 * @param bindings     协议绑定列表
 * @param physicalPath 站点根目录物理路径（取主应用程序 "/" 的虚拟目录）
 */
public record IisSite(int id, String name, String state, List<IisBinding> bindings, String physicalPath) {

    public IisSite {
        bindings = bindings == null ? List.of() : List.copyOf(bindings);
        physicalPath = physicalPath == null ? "" : physicalPath;
        state = state == null || state.isBlank() ? "Unknown" : state;
        name = name == null ? "" : name;
    }

    public boolean started() {
        return "started".equalsIgnoreCase(state);
    }

    /** 该站点需要被防护的 HTTP 端口（去重、升序）。 */
    public List<Integer> httpPorts() {
        Set<Integer> ports = new LinkedHashSet<>();
        for (IisBinding b : bindings) {
            if (b.protectable()) {
                ports.add(b.port());
            }
        }
        List<Integer> list = new ArrayList<>(ports);
        list.sort(Integer::compareTo);
        return list;
    }

    /** 该站点绑定的主机名，用于单行展示。 */
    public String hostText() {
        Set<String> hosts = new LinkedHashSet<>();
        for (IisBinding b : bindings) {
            if (b.protectable() && !b.host().isEmpty()) {
                hosts.add(b.host());
            }
        }
        return String.join(", ", hosts);
    }

    public String summary() {
        List<Integer> ports = httpPorts();
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("  [").append(state).append("]  ");
        if (ports.isEmpty()) {
            sb.append("无 HTTP 绑定");
        } else {
            sb.append("端口 ");
            for (int i = 0; i < ports.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(ports.get(i));
            }
            String h = hostText();
            if (!h.isEmpty()) {
                sb.append("  主机 ").append(h);
            }
        }
        if (!physicalPath.isEmpty()) {
            sb.append("  目录 ").append(physicalPath);
        }
        return sb.toString();
    }

    public String nameLower() {
        return name.toLowerCase(Locale.ROOT);
    }
}
