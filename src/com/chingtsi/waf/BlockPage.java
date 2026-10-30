/*
 * Chingtsi WAF - 拦截页面
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * 生成拦截/错误页。全部内联样式，不依赖外部资源，避免被拦截方探测资源路径。
 */
public final class BlockPage {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private BlockPage() {
    }

    public static String render(int code, String title, String detail, String ip,
                                List<RequestContext.Finding> findings) {
        StringBuilder ruleRows = new StringBuilder();
        if (findings != null) {
            for (RequestContext.Finding f : findings) {
                ruleRows.append("<tr><td>").append(esc(f.ruleId()))
                        .append("</td><td>").append(esc(f.message()))
                        .append("</td><td>").append(f.score())
                        .append("</td></tr>");
            }
        }

        return """
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>%s</title>
                <style>
                  :root{color-scheme:light dark}
                  *{box-sizing:border-box}
                  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
                       background:#0f1115;color:#e6e8ee;
                       font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif}
                  .card{width:min(680px,92vw);background:#181b22;border:1px solid #262b36;border-radius:14px;
                        padding:34px 36px;box-shadow:0 18px 50px rgba(0,0,0,.45)}
                  .code{font-size:13px;letter-spacing:.16em;text-transform:uppercase;color:#7f8899}
                  h1{margin:8px 0 14px;font-size:23px;font-weight:600;line-height:1.45}
                  p{margin:0 0 10px;color:#a8b0c0;line-height:1.75;font-size:14px}
                  .meta{margin-top:20px;padding-top:16px;border-top:1px solid #262b36;font-size:12.5px;color:#6f7889}
                  .meta div{margin:5px 0;display:flex;gap:10px}
                  .meta b{color:#8d97a8;min-width:92px;font-weight:500}
                  table{width:100%%;border-collapse:collapse;margin-top:14px;font-size:12.5px}
                  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #242936;color:#98a1b2}
                  th{color:#6f7889;font-weight:500}
                  .brand{margin-top:22px;font-size:11.5px;color:#4e5666;letter-spacing:.04em}
                  .brand b{color:#6b7688;font-weight:600}
                </style>
                </head>
                <body>
                  <div class="card">
                    <div class="code">HTTP %d</div>
                    <h1>%s</h1>
                    <p>%s</p>
                    %s
                    <div class="meta">
                      <div><b>客户端地址</b><span>%s</span></div>
                      <div><b>拦截时间</b><span>%s</span></div>
                      <div><b>站点</b><span>qingci.bond</span></div>
                    </div>
                    <div class="brand">Protected by <b>Chingtsi WAF</b> · Copyright &copy; 2026 <b>Chingtsi Studio</b></div>
                  </div>
                </body>
                </html>
                """.formatted(
                esc(title),
                code,
                esc(title),
                esc(detail),
                ruleRows.length() == 0 ? ""
                        : "<table><tr><th>规则</th><th>说明</th><th>分值</th></tr>" + ruleRows + "</table>",
                esc(ip),
                LocalDateTime.now().format(TS));
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
