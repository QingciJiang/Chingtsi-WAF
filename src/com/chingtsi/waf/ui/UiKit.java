/*
 * Chingtsi WAF - 控制台界面通用组件
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.ui;

import com.chingtsi.waf.geo.IpLocator;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.imageio.ImageIO;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/** 界面外观与通用小组件。 */
final class UiKit {

    static final Color OK = new Color(0x1B, 0x9E, 0x5F);
    static final Color WARN = new Color(0xD9, 0x7A, 0x0B);
    static final Color DANGER = new Color(0xD0, 0x3A, 0x3A);
    static final Color MUTED = new Color(0x6B, 0x72, 0x80);
    static final Color ACCENT = new Color(0x1F, 0x6F, 0xEB);
    static final Color ROW_BLOCK = new Color(0xFD, 0xEC, 0xEC);
    static final Color ROW_RATE = new Color(0xFE, 0xF3, 0xE0);
    static final Color ROW_UPSTREAM = new Color(0xFD, 0xF8, 0xE3);

    private UiKit() {
    }

    static Font bold(int size) {
        return new Font("Microsoft YaHei UI", Font.BOLD, size);
    }

    static Font plain(int size) {
        return new Font("Microsoft YaHei UI", Font.PLAIN, size);
    }

    /** IP 归属：本机 / 内网 / 公网。 */
    static String scope(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "未知";
        }
        String s = ip.startsWith("::ffff:") ? ip.substring(7) : ip;
        if (s.equals("::1") || s.equals("0:0:0:0:0:0:0:1") || s.startsWith("127.")) {
            return "本机";
        }
        if (s.startsWith("10.") || s.startsWith("192.168.") || s.startsWith("169.254.")) {
            return "内网";
        }
        if (s.startsWith("172.")) {
            String[] p = s.split("\\.");
            if (p.length > 1) {
                try {
                    int second = Integer.parseInt(p[1]);
                    if (second >= 16 && second <= 31) {
                        return "内网";
                    }
                } catch (NumberFormatException ignored) {
                    // 非法 IPv4，按公网处理
                }
            }
        }
        if (s.startsWith("fe80:") || s.startsWith("fc") || s.startsWith("fd")) {
            return "内网";
        }
        return "公网";
    }

    /** IP 属地短名（离线库，如“浙江 杭州”）；本机/内网直接返回，库缺失返回“-”。 */
    static String area(String ip) {
        return IpLocator.area(ip);
    }

    /** IP 属地完整信息（国 · 省 · 市 · 运营商）。 */
    static String areaDetail(String ip) {
        return IpLocator.detail(ip);
    }

    /** IP 风险等级：依据 WAF 原有判定结果聚合，仅用于展示。 */
    static String risk(WafEventLog.IpAgg a, int threshold) {
        int highBlock = Math.max(3, threshold);
        int highScore = Math.max(threshold, 1) * 2;
        if (a.blocks >= highBlock || a.maxScore >= highScore) {
            return "高危";
        }
        if (a.blocks > 0 || a.maxScore >= Math.max(threshold, 1)) {
            return "可疑";
        }
        return "正常";
    }

    static Color riskColor(String risk) {
        return switch (risk) {
            case "高危" -> DANGER;
            case "可疑" -> WARN;
            default -> OK;
        };
    }

    static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    // ---------------- 图标 ----------------

    /** 内置图标资源的全部尺寸（与 classpath 下的 logo-*.png 一致）。 */
    private static final int[] ICON_SIZES = {
            512, 256, 180, 128, 96, 72, 64, 56, 48, 40, 36, 32, 28, 24, 20, 16
    };

    private static final String ICON_PREFIX = "/com/chingtsi/waf/ui/logo-";

    /**
     * 取指定边长的图标位图。
     * 优先使用同尺寸的预渲染 PNG（小尺寸已针对像素网格优化，缩放会损失锐度）；
     * 无同尺寸资源时，从最近的更大尺寸逐步减半缩放，避免一次性大幅插值导致发虚。
     */
    static BufferedImage logoImage(int size) {
        URL exact = UiKit.class.getResource(ICON_PREFIX + size + ".png");
        if (exact != null) {
            BufferedImage img = readPng(exact);
            if (img != null) {
                return img;
            }
        }
        for (int s : ICON_SIZES) {
            if (s < size) {
                continue;
            }
            URL u = UiKit.class.getResource(ICON_PREFIX + s + ".png");
            BufferedImage img = u == null ? null : readPng(u);
            if (img != null) {
                return scaleTo(img, size);
            }
        }
        return null;
    }

    /** 标题栏 logo 用的 ImageIcon。 */
    static ImageIcon logoIcon(int size) {
        BufferedImage img = logoImage(size);
        return img == null ? new ImageIcon() : new ImageIcon(img);
    }

    /** 供 setIconImages 使用的多尺寸图标，让任务栏 / Alt+Tab 在各缩放比例下都取到原生尺寸。 */
    static List<Image> logoImages() {
        List<Image> images = new ArrayList<>();
        for (int s : ICON_SIZES) {
            URL u = UiKit.class.getResource(ICON_PREFIX + s + ".png");
            if (u == null) {
                continue;
            }
            BufferedImage img = readPng(u);
            if (img != null) {
                images.add(img);
            }
        }
        return images;
    }

    private static BufferedImage readPng(URL url) {
        try (InputStream in = url.openStream()) {
            BufferedImage raw = ImageIO.read(in);
            if (raw == null) {
                return null;
            }
            // 统一转为 ARGB，保证渐变透明边缘在任意外观下都不出现黑边
            BufferedImage argb = new BufferedImage(raw.getWidth(), raw.getHeight(),
                    BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = argb.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g.drawImage(raw, 0, 0, null);
            g.dispose();
            return argb;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static BufferedImage scaleTo(BufferedImage src, int size) {
        BufferedImage cur = src;
        int w = src.getWidth();
        int h = src.getHeight();
        while (w / 2 >= size && h / 2 >= size) {
            w /= 2;
            h /= 2;
            cur = drawScaled(cur, w, h);
        }
        return w == size && h == size ? cur : drawScaled(cur, size, size);
    }

    private static BufferedImage drawScaled(BufferedImage src, int w, int h) {
        BufferedImage out = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = out.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.drawImage(src, 0, 0, w, h, null);
        g.dispose();
        return out;
    }

    /** 顶部 KPI 数字卡。 */
    static final class KpiCard extends JPanel {

        private final JLabel value = new JLabel("0", SwingConstants.LEFT);
        private final JLabel sub = new JLabel(" ", SwingConstants.LEFT);
        private Color accent = ACCENT;

        KpiCard(String title, Color accent) {
            super(new BorderLayout(0, 2));
            this.accent = accent;
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));
            JLabel t = new JLabel(title);
            t.setFont(plain(12));
            t.setForeground(MUTED);
            value.setFont(bold(26));
            value.setForeground(accent);
            sub.setFont(plain(11));
            sub.setForeground(MUTED);
            add(t, BorderLayout.NORTH);
            add(value, BorderLayout.CENTER);
            add(sub, BorderLayout.SOUTH);
        }

        void set(String v, String subText) {
            value.setText(v);
            sub.setText(subText == null || subText.isEmpty() ? " " : subText);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(new Color(0xFF, 0xFF, 0xFF, 235));
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
            g2.setColor(new Color(accent.getRed(), accent.getGreen(), accent.getBlue(), 40));
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** 事件表整行着色渲染器。 */
    static final class EventRenderer extends DefaultTableCellRenderer {

        private final Runnable noop = () -> {
        };

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                String status = table.getModel() instanceof EventTableModel m
                        ? m.statusAt(table.convertRowIndexToModel(row)) : "PASS";
                switch (status) {
                    case "BLOCK", "BLACKLIST" -> c.setBackground(ROW_BLOCK);
                    case "BANNED", "RATE_LIMIT" -> c.setBackground(ROW_RATE);
                    case "UPSTREAM_TIMEOUT", "UPSTREAM_UNREACHABLE" -> c.setBackground(ROW_UPSTREAM);
                    default -> c.setBackground(table.getBackground());
                }
                c.setForeground("PASS".equals(status) ? new Color(0x37, 0x41, 0x51) : new Color(0x8A, 0x1C, 0x1C));
            }
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            noop.run();
            return c;
        }
    }

    /** IP 风险列渲染器。 */
    static final class RiskRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            String v = value == null ? "" : value.toString();
            if (!selected) {
                c.setBackground(table.getBackground());
                setForeground(riskColor(v));
                setText("● " + v);
            } else {
                setText(v);
            }
            setFont(bold(12));
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            return c;
        }
    }

    /** 斑马纹 + 左内边距的普通渲染器。 */
    static final class PlainRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                c.setBackground(row % 2 == 0 ? table.getBackground()
                        : new Color(0xF7, 0xF8, 0xFA));
            }
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            return c;
        }
    }

    /** 事件表模型接口，供渲染器读取状态。 */
    interface EventTableModel {
        String statusAt(int modelRow);
    }
}
