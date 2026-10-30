/*
 * Chingtsi WAF - IIS 配置快照
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 某一时刻的 IIS 站点视图。
 *
 * @param time           采样时间
 * @param source         数据来源说明（applicationHost.config / appcmd / 无）
 * @param note           附加说明（失败原因等）
 * @param sites          IIS 站点列表
 * @param listeningPorts 本机 127.0.0.1 上确认可连接的站点端口
 */
public record IisSnapshot(long time, String source, String note, List<IisSite> sites, Set<Integer> listeningPorts) {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    public IisSnapshot {
        sites = sites == null ? List.of() : List.copyOf(sites);
        listeningPorts = listeningPorts == null ? Set.of() : Set.copyOf(listeningPorts);
        source = source == null ? "" : source;
        note = note == null ? "" : note;
    }

    public static IisSnapshot empty(String note) {
        return new IisSnapshot(System.currentTimeMillis(), "无", note, List.of(), Set.of());
    }

    public boolean found() {
        return !sites.isEmpty();
    }

    /** 全部需要防护的 IIS HTTP 端口，去重升序。 */
    public List<Integer> httpPorts() {
        Set<Integer> set = new LinkedHashSet<>();
        for (IisSite s : sites) {
            set.addAll(s.httpPorts());
        }
        List<Integer> list = new ArrayList<>(set);
        list.sort(Integer::compareTo);
        return list;
    }

    /** 站点端口是否在本机处于监听状态。 */
    public boolean portAlive(int port) {
        return listeningPorts.contains(port);
    }

    /** 状态栏使用的短摘要，例如 "IIS 端口 80、8080（2 个站点）"。 */
    public String shortSummary() {
        List<Integer> ports = httpPorts();
        if (ports.isEmpty()) {
            return "未发现 IIS 站点";
        }
        StringBuilder sb = new StringBuilder("IIS 端口 ");
        for (int i = 0; i < ports.size(); i++) {
            if (i > 0) {
                sb.append('、');
            }
            sb.append(ports.get(i));
        }
        sb.append("（").append(sites.size()).append(" 个站点）");
        return sb.toString();
    }

    public String sampleTimeText() {
        return LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(time),
                java.time.ZoneId.systemDefault()).format(FMT);
    }

    /** 防护配置页用的多行明细。 */
    public String detailText() {
        StringBuilder sb = new StringBuilder();
        sb.append("数据来源   : ").append(source).append("   采样 ").append(sampleTimeText()).append('\n');
        if (!note.isEmpty()) {
            sb.append("说明       : ").append(note).append('\n');
        }
        if (sites.isEmpty()) {
            sb.append("IIS 站点   : 未检测到（可能未安装 IIS，或当前账户无权读取配置）\n");
            return sb.toString();
        }
        List<Integer> ports = httpPorts();
        sb.append("防护端口   : ");
        if (ports.isEmpty()) {
            sb.append("无 HTTP 绑定\n");
        } else {
            sb.append(ports.toString().replace("[", "").replace("]", "").replace(", ", "、"))
                    .append("   （共 ").append(sites.size()).append(" 个站点）\n");
        }
        for (IisSite s : sites) {
            sb.append(String.format("  · %-22s %s%n", s.name(), s.summary().replace(s.name() + "  ", "")));
            for (IisBinding b : s.bindings()) {
                sb.append("      ").append(b.describe());
                if (b.protectable()) {
                    sb.append(portAliveText(b, this));
                }
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    private static String portAliveText(IisBinding b, IisSnapshot snap) {
        return snap.portAlive(b.port()) ? "   ← 本机监听中" : "   ← 未监听";
    }
}
