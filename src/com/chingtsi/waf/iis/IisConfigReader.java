/*
 * Chingtsi WAF - IIS 配置读取
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 读取本机 IIS 配置，得到站点与端口清单。
 * <p>优先级：</p>
 * <ol>
 *   <li>{@code iis.config.file} 指定的文件；</li>
 *   <li>{@code %windir%\System32\inetsrv\config\applicationHost.config}；</li>
 *   <li>{@code %windir%\System32\inetsrv\appcmd.exe list sites /xml}；</li>
 *   <li>全部不可用时返回空快照，由调用方回退到配置里的固定监听端口。</li>
 * </ol>
 * 全过程只读，不修改 IIS 配置。
 */
public final class IisConfigReader {

    private IisConfigReader() {
    }

    /** 读取当前 IIS 站点快照。不会抛异常。 */
    public static IisSnapshot read(Path override) {
        long now = System.currentTimeMillis();

        Path conf = override;
        if (conf == null) {
            String windir = System.getenv("windir");
            if (windir == null || windir.isBlank()) {
                windir = System.getenv("SystemRoot");
            }
            if (windir != null && !windir.isBlank()) {
                conf = Path.of(windir, "System32", "inetsrv", "config", "applicationHost.config");
            }
        }

        if (conf != null && Files.isRegularFile(conf)) {
            try {
                List<IisSite> sites = parseApplicationHost(Files.readAllBytes(conf));
                return new IisSnapshot(now, "applicationHost.config", conf.toString(),
                        sites, probePorts(sites));
            } catch (Exception e) {
                String msg = "解析 " + conf + " 失败：" + e.getMessage();
                IisSnapshot viaAppcmd = readByAppcmd(now, msg);
                if (viaAppcmd != null) {
                    return viaAppcmd;
                }
                return IisSnapshot.empty(msg);
            }
        }

        IisSnapshot viaAppcmd = readByAppcmd(now, "未找到 applicationHost.config");
        if (viaAppcmd != null) {
            return viaAppcmd;
        }
        return IisSnapshot.empty("未检测到 IIS：applicationHost.config 与 appcmd.exe 均不可用");
    }

    // ------------------------------------------------------------------
    //  applicationHost.config
    // ------------------------------------------------------------------

    static List<IisSite> parseApplicationHost(byte[] xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(false);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setExpandEntityReferences(false);
        DocumentBuilder b = f.newDocumentBuilder();
        Document doc = b.parse(new ByteArrayInputStream(xml));

        List<IisSite> sites = new ArrayList<>();
        NodeList siteNodes = doc.getElementsByTagName("site");
        for (int i = 0; i < siteNodes.getLength(); i++) {
            Node n = siteNodes.item(i);
            if (!(n instanceof Element site)) {
                continue;
            }
            // 排除 <sites> 之外的同类节点：必须有 name 属性
            String name = site.getAttribute("name");
            if (name == null || name.isEmpty()) {
                continue;
            }
            int id = parseInt(site.getAttribute("id"), i + 1);

            List<IisBinding> bindings = new ArrayList<>();
            NodeList bindingNodes = site.getElementsByTagName("binding");
            for (int j = 0; j < bindingNodes.getLength(); j++) {
                if (bindingNodes.item(j) instanceof Element be) {
                    bindings.add(IisBinding.parse(be.getAttribute("protocol"),
                            be.getAttribute("bindingInformation")));
                }
            }

            String physical = "";
            NodeList vdirs = site.getElementsByTagName("virtualDirectory");
            for (int j = 0; j < vdirs.getLength(); j++) {
                if (vdirs.item(j) instanceof Element ve) {
                    String p = ve.getAttribute("physicalPath");
                    if (p != null && !p.isBlank()) {
                        physical = p;
                        break;
                    }
                }
            }
            String autoStart = site.getAttribute("serverAutoStart");
            String state = "true".equalsIgnoreCase(autoStart) || autoStart.isEmpty() ? "Started" : "Stopped";
            sites.add(new IisSite(id, name, state, bindings, physical));
        }
        return sites;
    }

    // ------------------------------------------------------------------
    //  appcmd 兜底
    // ------------------------------------------------------------------

    private static IisSnapshot readByAppcmd(long now, String note) {
        String windir = System.getenv("windir");
        if (windir == null || windir.isBlank()) {
            windir = System.getenv("SystemRoot");
        }
        if (windir == null || windir.isBlank()) {
            return null;
        }
        Path appcmd = Path.of(windir, "System32", "inetsrv", "appcmd.exe");
        if (!Files.isRegularFile(appcmd)) {
            return null;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(appcmd.toString(), "list", "site", "/xml");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            byte[] out;
            try (InputStream in = p.getInputStream()) {
                out = in.readAllBytes();
            }
            if (!p.waitFor(8, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            if (p.exitValue() != 0) {
                return null;
            }
            List<IisSite> sites = parseAppcmdXml(out);
            return new IisSnapshot(now, "appcmd", note + "；已改用 appcmd 读取", sites, probePorts(sites));
        } catch (Exception e) {
            return null;
        }
    }

    static List<IisSite> parseAppcmdXml(byte[] xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(false);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        List<IisSite> sites = new ArrayList<>();
        NodeList nodes = doc.getElementsByTagName("SITE");
        for (int i = 0; i < nodes.getLength(); i++) {
            if (!(nodes.item(i) instanceof Element e)) {
                continue;
            }
            String name = firstAttr(e, "SITE.NAME", "name");
            if (name.isEmpty()) {
                continue;
            }
            int id = parseInt(firstAttr(e, "SITE.ID", "id"), i + 1);
            String state = firstAttr(e, "state", "STATE");
            List<IisBinding> bindings = new ArrayList<>();
            String raw = firstAttr(e, "bindings", "BINDINGS");
            for (String part : raw.split(",")) {
                String t = part.trim();
                if (t.isEmpty()) {
                    continue;
                }
                int slash = t.indexOf('/');
                if (slash <= 0) {
                    continue;
                }
                bindings.add(IisBinding.parse(t.substring(0, slash), t.substring(slash + 1)));
            }
            String physical = firstAttr(e, "physicalPath", "PHYSICALPATH");
            sites.add(new IisSite(id, name, state.isEmpty() ? "Unknown" : state, bindings, physical));
        }
        return sites;
    }

    private static String firstAttr(Element e, String a, String b) {
        String v = e.getAttribute(a);
        if (v == null || v.isEmpty()) {
            v = e.getAttribute(b);
        }
        return v == null ? "" : v.trim();
    }

    // ------------------------------------------------------------------
    //  端口连通性探测
    // ------------------------------------------------------------------

    /** 探测站点端口在本机 127.0.0.1 上是否可连接（用于区分“已停止”的站点）。 */
    static Set<Integer> probePorts(List<IisSite> sites) {
        Set<Integer> ports = new LinkedHashSet<>();
        for (IisSite s : sites) {
            ports.addAll(s.httpPorts());
        }
        Set<Integer> alive = new LinkedHashSet<>();
        for (int port : ports) {
            if (probe(port)) {
                alive.add(port);
            }
        }
        return alive;
    }

    public static boolean probe(int port) {
        if (port <= 0 || port > 65535) {
            return false;
        }
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 300);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static int parseInt(String v, int def) {
        try {
            return Integer.parseInt(v.trim());
        } catch (Exception e) {
            return def;
        }
    }

    /** 仅供离线自测：从文本文件读入 applicationHost.config 片段。 */
    public static IisSnapshot readFile(Path file) throws IOException {
        List<IisSite> sites = null;
        try {
            sites = parseApplicationHost(Files.readAllBytes(file));
        } catch (Exception e) {
            throw new IOException(e.getMessage(), e);
        }
        return new IisSnapshot(System.currentTimeMillis(), file.toString(), "",
                sites, probePorts(sites));
    }

    static String decode(byte[] raw) {
        return new String(raw, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
    }
}
