/*
 * Chingtsi WAF - 反向代理与检测主流程
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 请求处理链：
 * <pre>
 * 取真实 IP → 黑名单 → 限流 → 方法校验 → 读取请求体 → 规则检测 → 转发上游 → 回写响应
 * </pre>
 * 白名单 IP 跳过全部检测，直接代理；白名单文件会每 5 秒检查一次是否变更，变更后自动热加载。
 * 白名单放行的请求在审计日志中判定为 "WHITELIST"。
 */
public final class ProxyHandler implements HttpHandler {

    /** 逐跳首部，不允许透传。 */
    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "content-length",
            "host", "expect", "proxy-connection"
    );

    private final WafConfig cfg;
    /** 规则引擎可被热加载线程整体替换，故用原子引用持有。 */
    private final AtomicReference<RuleEngine> engineRef;
    private final Path whitelistFile;
    /** 白名单集合；文件变更时会被热加载替换。 */
    private volatile IpSet whitelist;
    /** 白名单文件上次检测到的修改时间戳。 */
    private volatile long whitelistStamp;
    /** 上次检查白名单文件的时间点，用于限制检查频率。 */
    private volatile long lastWhitelistCheck;
    private final IpSet blacklist;
    private final RateLimiter limiter;
    private final AccessLog log;
    private final HttpClient upstream;
    private final Set<String> allowedMethods;
    /** 本监听器对应的上游基地址；按 IIS 站点端口建监听器时指向 127.0.0.1:<站点端口>。 */
    private final String upstreamBase;

    /**
     * @param whitelistFile    白名单文件路径；文件变更后会自动热加载，可为 null（则不加载白名单）
     * @param upstreamOverride 指定上游基地址（如 {@code http://127.0.0.1:80}）；
     *                         为 null 时使用配置项 upstream.base
     */
    public ProxyHandler(WafConfig cfg, AtomicReference<RuleEngine> engineRef, Path whitelistFile,
                        IpSet blacklist, RateLimiter limiter, AccessLog log, String upstreamOverride) {
        this.cfg = cfg;
        this.engineRef = engineRef;
        this.whitelistFile = whitelistFile;
        this.whitelist = IpSet.load(whitelistFile);
        this.blacklist = blacklist;
        this.limiter = limiter;
        this.log = log;
        this.upstreamBase = upstreamOverride == null || upstreamOverride.isBlank()
                ? cfg.upstreamBase() : upstreamOverride.trim();
        this.upstream = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        Set<String> methods = new java.util.HashSet<>();
        for (String m : cfg.allowMethods().split(",")) {
            String t = m.trim().toUpperCase(Locale.ROOT);
            if (!t.isEmpty()) {
                methods.add(t);
            }
        }
        this.allowedMethods = Set.copyOf(methods);
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        long start = System.currentTimeMillis();
        String reqId = UUID.randomUUID().toString().substring(0, 8);
        String clientIp = clientIp(ex);

        try {
            String method = ex.getRequestMethod().toUpperCase(Locale.ROOT);
            URI uri = ex.getRequestURI();

            Map<String, List<String>> headerMap = new LinkedHashMap<>();
            ex.getRequestHeaders().forEach((k, v) ->
                    headerMap.put(k.toLowerCase(Locale.ROOT), new ArrayList<>(v)));

            byte[] body;
            try {
                body = readLimited(ex.getRequestBody(), (int) Math.min(cfg.maxBodyBytes(), 512L * 1024 * 1024));
            } catch (TooLarge e) {
                RequestContext empty = new RequestContext(clientIp, remoteAddr(ex), method,
                        uri.getRawPath(), uri.getRawQuery(), ex.getProtocol(), headerMap, new byte[0]);
                fail(ex, empty, 413, "请求体过大",
                        "请求体超过 " + cfg.maxBodyBytes() + " 字节上限，已被拦截。", reqId, start, "BODY_TOO_LARGE");
                return;
            }

            RequestContext ctx = new RequestContext(clientIp, remoteAddr(ex), method,
                    uri.getRawPath(), uri.getRawQuery(), ex.getProtocol(), headerMap, body);

            ensureWhitelistFresh();
            boolean trusted = whitelist.contains(clientIp);

            if (!trusted) {
                if (blacklist.contains(clientIp)) {
                    fail(ex, ctx, 403, "来源地址已被封禁",
                            "该 IP 位于站点黑名单中，禁止访问。", reqId, start, "BLACKLIST");
                    return;
                }

                if (limiter.isBanned(clientIp)) {
                    fail(ex, ctx, 403, "访问频率异常",
                            "短时间内请求过于频繁，已被临时封禁，请稍后再试。", reqId, start, "BANNED");
                    return;
                }

                RateLimiter.Decision d = limiter.check(clientIp);
                if (d == RateLimiter.Decision.RATE_LIMITED || d == RateLimiter.Decision.BANNED) {
                    Heads.retryAfter(ex, cfg.banSeconds());
                    fail(ex, ctx, 429, "请求过于频繁",
                            "已触发访问频率限制（每 " + cfg.rateWindowSeconds() + " 秒最多 "
                                    + cfg.rateLimit() + " 次），当前来源已被临时封禁 "
                                    + cfg.banSeconds() + " 秒。", reqId, start, "RATE_LIMIT");
                    return;
                }

                if (!allowedMethods.contains(method)) {
                    fail(ex, ctx, 405, "请求方法不被允许",
                            "站点不接受 " + method + " 方法的请求。", reqId, start, "METHOD_DENIED");
                    return;
                }

                RuleEngine.Verdict v = engineRef.get().inspect(ctx);
                if (v.blocked()) {
                    fail(ex, ctx, 403, "请求已被安全策略拦截",
                            "本次请求触发了站点的 Web 应用防火墙规则，累计异常分值 " + v.score()
                                    + "，已达到拦截阈值，请求未转发到后端。", reqId, start, "RULE_BLOCK");
                    return;
                }
            }

            forward(ex, ctx, reqId, start, trusted ? "WHITELIST" : "PASS");
        } catch (Exception e) {
            String msg = e.getClass().getSimpleName() + ": " + e.getMessage();
            System.out.println("[ERROR] " + reqId + " " + msg);
            try {
                RequestContext ctx = new RequestContext(clientIp, remoteAddr(ex), ex.getRequestMethod(),
                        ex.getRequestURI().getRawPath(), ex.getRequestURI().getRawQuery(),
                        ex.getProtocol(), Map.of(), new byte[0]);
                fail(ex, ctx, 502, "网关内部错误",
                        "处理该请求时发生异常，已记录日志。", reqId, start, "INTERNAL_ERROR");
            } catch (Exception ignored) {
                // 响应已发出，忽略
            }
        } finally {
            try {
                ex.close();
            } catch (Exception ignored) {
                // 忽略
            }
        }
    }

    private void forward(HttpExchange ex, RequestContext ctx, String reqId, long start, String passStatus)
            throws IOException {
        URI target;
        try {
            target = buildTarget(ex);
        } catch (Exception e) {
            fail(ex, ctx, 400, "请求地址非法", "无法解析的请求路径。", reqId, start, "BAD_URI");
            return;
        }

        String method = ctx.method();
        HttpRequest.Builder rb = HttpRequest.newBuilder(target)
                .timeout(Duration.ofMillis(cfg.upstreamTimeoutMs()));

        boolean mayHaveBody = !"GET".equals(method) && !"HEAD".equals(method)
                && !"OPTIONS".equals(method) && ctx.body().length > 0;
        rb.method(method, mayHaveBody
                ? HttpRequest.BodyPublishers.ofByteArray(ctx.body())
                : HttpRequest.BodyPublishers.noBody());

        for (Map.Entry<String, List<String>> e : ctx.headers().entrySet()) {
            String name = e.getKey().toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(name)) {
                continue;
            }
            for (String v : e.getValue()) {
                try {
                    rb.header(name, v);
                } catch (IllegalArgumentException ignored) {
                    // HttpClient 受限首部，跳过
                }
            }
        }

        // 保留原始 Host，使 IIS 能按主机名匹配到对应站点（需 -Djdk.httpclient.allowRestrictedHeaders=host）
        String originHost = ctx.header("host");
        if (originHost != null && !originHost.isBlank()) {
            safeHeader(rb, "Host", originHost);
        }

        String priorXff = ctx.header("x-forwarded-for");
        String xff = (priorXff == null || priorXff.isBlank())
                ? ctx.clientIp()
                : priorXff + ", " + ctx.clientIp();
        safeHeader(rb, "X-Forwarded-For", xff);
        safeHeader(rb, "X-Real-IP", ctx.clientIp());
        safeHeader(rb, "X-Forwarded-Proto", "http");
        safeHeader(rb, "X-Chingtsi-WAF", WafMain.VERSION);
        safeHeader(rb, "X-Request-Id", reqId);

        HttpRequest request = rb.build();
        long elapsed;
        try {
            HttpResponse<InputStream> resp = upstream.send(request, HttpResponse.BodyHandlers.ofInputStream());
            int code = resp.statusCode();

            Headers out = ex.getResponseHeaders();
            resp.headers().map().forEach((k, v) -> {
                if (!HOP_BY_HOP.contains(k.toLowerCase(Locale.ROOT))) {
                    out.put(k, new ArrayList<>(v));
                }
            });
            out.remove("Server");
            out.set("Server", cfg.serverName());
            out.set("X-WAF-Engine", WafMain.PRODUCT + "/" + WafMain.VERSION);
            out.set("X-Request-Id", reqId);

            boolean noBody = "HEAD".equals(method) || code == 204 || code == 304 || code < 200;
            if (noBody) {
                ex.sendResponseHeaders(code, -1);
                try (InputStream ignored = resp.body()) {
                    // 主动关闭流
                }
            } else {
                ex.sendResponseHeaders(code, 0);
                try (InputStream in = resp.body(); OutputStream os = ex.getResponseBody()) {
                    in.transferTo(os);
                }
            }
            elapsed = System.currentTimeMillis() - start;
            log.record(ctx, passStatus, code, ctx.score(), elapsed, null);
        } catch (java.net.http.HttpTimeoutException e) {
            fail(ex, ctx, 504, "后端响应超时", "上游服务器未在约定时间内响应。", reqId, start, "UPSTREAM_TIMEOUT");
        } catch (java.io.IOException e) {
            fail(ex, ctx, 502, "后端不可达",
                    "无法连接到上游服务器，请稍后重试。", reqId, start, "UPSTREAM_UNREACHABLE");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail(ex, ctx, 502, "请求被中断", "内部调度被中断。", reqId, start, "INTERRUPTED");
        }
    }

    private static void safeHeader(HttpRequest.Builder rb, String name, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        try {
            rb.header(name, value);
        } catch (IllegalArgumentException ignored) {
            // 忽略受限首部
        }
    }

    private URI buildTarget(HttpExchange ex) {
        URI u = ex.getRequestURI();
        String path = u.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        String query = u.getRawQuery();
        String base = upstreamBase;
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        String full = base + path + (query == null || query.isEmpty() ? "" : "?" + query);
        return URI.create(full);
    }

    /** 若白名单文件在最近 5 秒内被修改，则重新加载（供控制台添加白名单后无需重启即可生效）。 */
    private void ensureWhitelistFresh() {
        long now = System.currentTimeMillis();
        if (now - lastWhitelistCheck < 5_000L) {
            return;
        }
        lastWhitelistCheck = now;
        Path f = whitelistFile;
        if (f == null) {
            return;
        }
        try {
            if (!Files.isRegularFile(f)) {
                return;
            }
            long m = Files.getLastModifiedTime(f).toMillis();
            if (m == whitelistStamp) {
                return;
            }
            whitelistStamp = m;
            this.whitelist = IpSet.load(f);
            System.out.println("[IP   ] 白名单文件已变更，重新加载 " + f + " (" + whitelist.size() + " 条)");
        } catch (IOException ignored) {
        }
    }

    private void fail(HttpExchange ex, RequestContext ctx, int code, String title, String detail,
                      String reqId, long start, String status) throws IOException {
        if (ex.getResponseCode() != -1) {
            return;
        }
        byte[] html = BlockPage.render(code, title, detail, ctx.clientIp(), ctx.findings())
                .getBytes(StandardCharsets.UTF_8);
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", "text/html; charset=UTF-8");
        h.set("Server", cfg.serverName());
        h.set("X-WAF-Engine", WafMain.PRODUCT + "/" + WafMain.VERSION);
        h.set("X-Request-Id", reqId);
        try {
            ex.sendResponseHeaders(code, html.length);
            try (OutputStream os = ex.getResponseBody()) {
                if (!"HEAD".equals(ctx.method())) {
                    os.write(html);
                }
            }
        } catch (IOException e) {
            // 客户端可能已断开
        }
        long elapsed = System.currentTimeMillis() - start;
        log.record(ctx, status, code, ctx.score(), elapsed, null);
    }

    private String clientIp(HttpExchange ex) {
        Headers h = ex.getRequestHeaders();
        if (cfg.trustCfConnectingIp()) {
            String cf = h.getFirst("CF-Connecting-IP");
            if (cf != null && !cf.isBlank()) {
                return cf.trim();
            }
        }
        String xff = h.getFirst("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String xri = h.getFirst("X-Real-IP");
        if (xri != null && !xri.isBlank()) {
            return xri.trim();
        }
        InetSocketAddress a = ex.getRemoteAddress();
        if (a == null || a.getAddress() == null) {
            return "0.0.0.0";
        }
        String ip = a.getAddress().getHostAddress();
        if (ip != null && ip.startsWith("::ffff:")) {
            return ip.substring(7);
        }
        return ip == null ? "0.0.0.0" : ip;
    }

    /** TCP 对端地址，仅用于日志取证（隧道场景下通常为 127.0.0.1）。 */
    private static String remoteAddr(HttpExchange ex) {
        InetSocketAddress a = ex.getRemoteAddress();
        if (a == null || a.getAddress() == null) {
            return "";
        }
        String ip = a.getAddress().getHostAddress();
        if (ip != null && ip.startsWith("::ffff:")) {
            ip = ip.substring(7);
        }
        return ip == null ? "" : ip;
    }

    private static byte[] readLimited(InputStream in, int limit) throws IOException, TooLarge {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(Math.min(limit, 16384));
        byte[] chunk = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(chunk)) > 0) {
            total += n;
            if (total > limit) {
                throw new TooLarge();
            }
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }

    private static final class TooLarge extends Exception {
        private static final long serialVersionUID = 1L;
    }

    /** 响应头辅助。 */
    static final class Heads {
        private Heads() {
        }

        static void retryAfter(HttpExchange ex, int seconds) {
            ex.getResponseHeaders().set("Retry-After", String.valueOf(seconds));
        }
    }
}
