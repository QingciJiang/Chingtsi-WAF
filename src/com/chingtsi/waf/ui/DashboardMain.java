/*
 * Chingtsi WAF - 图形控制台入口
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 说明：本控制台主要读取 logs/waf.log 与 conf/rules 目录做展示，不参与请求判定；
 * 仅在通过白名单管理口令验证后，可向 conf/ip-whitelist.txt 写入白名单条目。
 */
package com.chingtsi.waf.ui;

import com.chingtsi.waf.WafConfig;
import com.chingtsi.waf.geo.IpLocator;
import com.chingtsi.waf.iis.IisConfigReader;
import com.chingtsi.waf.security.PasscodeDialog;
import com.chingtsi.waf.security.PasscodeGuard;
import com.chingtsi.waf.iis.IisFrontPorts;
import com.chingtsi.waf.iis.IisMonitor;
import com.chingtsi.waf.iis.IisSnapshot;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.JTableHeader;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** 主窗口。 */
public final class DashboardMain {

    public static final String VERSION = com.chingtsi.waf.WafMain.VERSION;

    private DashboardMain() {
    }

    public static void main(String[] args) {
        setupLookAndFeel();
        Path home = resolveHome();
        // 离线 IP 属地库（data/ip2region.db）；缺失时属地列显示 “-”，不影响其它功能
        IpLocator.init(home);
        SwingUtilities.invokeLater(() -> {
            Dashboard frame = new Dashboard(home);
            frame.setVisible(true);
        });
    }

    private static void setupLookAndFeel() {
        try {
            // 开源外观 FlatLaf（Apache-2.0）；缺失时自动回退系统外观
            Class<?> laf = Class.forName("com.formdev.flatlaf.FlatLightLaf");
            laf.getMethod("setup").invoke(null);
        } catch (Throwable ignored) {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored2) {
                // 使用默认 Metal 外观
            }
        }
        UIManager.put("defaultFont", new Font("Microsoft YaHei UI", Font.PLAIN, 13));
        UIManager.put("Table.showHorizontalLines", Boolean.TRUE);
        UIManager.put("Table.showVerticalLines", Boolean.FALSE);
        UIManager.put("Table.rowHeight", 28);
        UIManager.put("Component.arc", 10);
        UIManager.put("Button.arc", 10);
        UIManager.put("TextComponent.arc", 10);
    }

    static Path resolveHome() {
        String h = System.getProperty("waf.home");
        if (h != null && !h.isBlank()) {
            return Path.of(h).toAbsolutePath().normalize();
        }
        try {
            Path self = Path.of(DashboardMain.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            Path appDir = Files.isDirectory(self) ? self : self.getParent();
            if (appDir != null && appDir.getFileName() != null
                    && "app".equalsIgnoreCase(appDir.getFileName().toString())
                    && appDir.getParent() != null) {
                return appDir.getParent();
            }
            return appDir == null ? Path.of(".").toAbsolutePath() : appDir;
        } catch (Exception e) {
            return Path.of(".").toAbsolutePath().normalize();
        }
    }

    // ==================================================================
    //  主窗口
    // ==================================================================

    static final class Dashboard extends JFrame {

        private final Path home;
        private final Path securityFile;
        private final WafConfig cfg;
        private final WafEventLog log;

        private final List<WafEvent> visibleEvents = new ArrayList<>();
        private final List<WafEventLog.IpAgg> visibleIps = new ArrayList<>();
        private final List<WafEvent> detailEvents = new ArrayList<>();

        private final EventModel eventModel = new EventModel();
        private final IpModel ipModel = new IpModel();
        private final EventModel detailModel = new EventModel();

        private final JTable eventTable = new JTable(eventModel);
        private final JTable ipTable = new JTable(ipModel);
        private final JTable detailTable = new JTable(detailModel);

        private final JTextField searchField = new JTextField();
        private final JComboBox<String> statusFilter =
                new JComboBox<>(new String[]{"全部事件", "仅拦截事件", "仅限流/封禁", "仅放行", "仅上游异常"});
        private final JCheckBox onlyAbnormal = new JCheckBox("仅异常 IP");
        private final JCheckBox autoRefresh = new JCheckBox("自动刷新", true);
        private final JLabel statusPill = new JLabel("检测中…");
        private final JLabel statusBar = new JLabel(" ");
        private final JLabel clockBar = new JLabel(" ");
        private final JTabbedPane tabs = new JTabbedPane();

        private final UiKit.KpiCard kpiTotal = new UiKit.KpiCard("累计请求", UiKit.ACCENT);
        private final UiKit.KpiCard kpiBlock = new UiKit.KpiCard("拦截事件", UiKit.DANGER);
        private final UiKit.KpiCard kpiIps = new UiKit.KpiCard("异常来源 IP", UiKit.WARN);
        private final UiKit.KpiCard kpiRate = new UiKit.KpiCard("拦截率", UiKit.OK);

        private String selectedIp = "";
        private JButton addWhiteBtn;
        private int probeTick;

        /** 最近一次读取到的 IIS 站点快照与端口映射，供状态栏与配置页共用。 */
        private volatile IisSnapshot iisSnapshot = IisSnapshot.empty("尚未读取");
        private volatile Map<Integer, Integer> iisPlan = Map.of();
        private JLabel specLabel;
        private boolean serviceProbed;

        Dashboard(Path home) {
            this.home = home;
            this.cfg = loadConfig(home);
            this.securityFile = home.resolve("conf").resolve("security.properties");
            this.log = new WafEventLog(cfg.logFile());

            setTitle("Chingtsi WAF 控制台 " + VERSION);
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            setMinimumSize(new Dimension(1080, 680));
            setSize(1320, 840);
            setLocationRelativeTo(null);
            applyIcon();

            JPanel root = new JPanel(new BorderLayout(0, 0));
            root.setBackground(new Color(0xF3, 0xF5, 0xF8));
            root.add(buildHeader(), BorderLayout.NORTH);
            root.add(buildBody(), BorderLayout.CENTER);
            root.add(buildStatusBar(), BorderLayout.SOUTH);
            setContentPane(root);
            installTabShortcuts(root);

            log.poll();
            refreshAll();

            Timer timer = new Timer(1000, e -> {
                if (autoRefresh.isSelected()) {
                    int added = log.poll();
                    if (added > 0) {
                        refreshAll();
                    }
                }
                probeTick++;
                if (probeTick % 3 == 0) {
                    probeService();
                }
                clockBar.setText("刷新于 " + LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("HH:mm:ss")));
            });
            timer.start();
            probeService();
            applyStartupHint();
            ensureFirstRunPassword();
        }

        // ---------------- 顶部 ----------------

        private Component buildHeader() {
            JPanel header = new JPanel(new BorderLayout());
            header.setBackground(Color.WHITE);
            header.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0xE3, 0xE7, 0xEE)),
                    BorderFactory.createEmptyBorder(12, 18, 12, 18)));

            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
            left.setOpaque(false);
            ImageIcon logo = UiKit.logoIcon(48);
            JLabel icon = new JLabel(logo);
            left.add(icon);

            JPanel titles = new JPanel();
            titles.setOpaque(false);
            titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
            JLabel t1 = new JLabel("Chingtsi WAF 控制台");
            t1.setFont(UiKit.bold(19));
            t1.setForeground(new Color(0x1F, 0x29, 0x37));
            JLabel t2 = new JLabel("v" + VERSION + " · 正在自动检查 IIS 站点…");
            specLabel = t2;
            t2.setFont(UiKit.plain(12));
            t2.setForeground(UiKit.MUTED);
            titles.add(t1);
            titles.add(Box.createVerticalStrut(3));
            titles.add(t2);
            left.add(titles);

            JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 4));
            right.setOpaque(false);
            statusPill.setOpaque(true);
            statusPill.setFont(UiKit.bold(12));
            statusPill.setBorder(BorderFactory.createEmptyBorder(5, 12, 5, 12));
            right.add(statusPill);

            JButton openLog = new JButton("日志目录");
            openLog.addActionListener(e -> openFolder(cfg.logFile().getParent()));
            JButton openConf = new JButton("配置目录");
            openConf.addActionListener(e -> openFolder(home.resolve("conf")));
            right.add(openLog);
            right.add(openConf);

            JButton passBtn = new JButton("白名单口令");
            passBtn.addActionListener(e -> managePasscode());
            right.add(passBtn);

            header.add(left, BorderLayout.WEST);
            header.add(right, BorderLayout.EAST);
            return header;
        }

        private Component buildBody() {
            JPanel body = new JPanel(new BorderLayout(0, 10));
            body.setOpaque(false);
            body.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

            JPanel kpis = new JPanel(new GridLayout(1, 4, 12, 0));
            kpis.setOpaque(false);
            kpis.setPreferredSize(new Dimension(10, 86));
            kpis.add(kpiTotal);
            kpis.add(kpiBlock);
            kpis.add(kpiIps);
            kpis.add(kpiRate);
            body.add(kpis, BorderLayout.NORTH);

            tabs.setFont(UiKit.plain(13));
            tabs.addTab("防护事件", buildEventPanel());
            tabs.addTab("访问者 IP", buildIpPanel());
            tabs.addTab("IP 详情", buildDetailPanel());
            tabs.addTab("防护配置", buildConfigPanel());
            for (int i = 0; i < tabs.getTabCount(); i++) {
                tabs.setToolTipTextAt(i, "快捷键 Alt+" + (i + 1));
            }
            body.add(tabs, BorderLayout.CENTER);
            return body;
        }

        private Component buildEventPanel() {
            JPanel panel = new JPanel(new BorderLayout(0, 8));
            panel.setOpaque(false);
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            bar.setOpaque(false);
            searchField.setColumns(22);
            searchField.setToolTipText("按 IP、属地、路径、命中规则、User-Agent 过滤");
            searchField.putClientProperty("JTextField.placeholderText", "搜索 IP / 属地 / 路径 / 规则 / UA");
            bar.add(new JLabel("搜索"));
            bar.add(searchField);
            statusFilter.setPreferredSize(new Dimension(150, 28));
            bar.add(statusFilter);
            bar.add(new JCheckBox("暂停") {{
                addActionListener(e -> autoRefresh.setSelected(!isSelected()));
            }});
            JButton export = new JButton("导出当前视图 CSV");
            export.addActionListener(e -> exportEvents());
            bar.add(export);
            JLabel hint = new JLabel("双击某行可查看该 IP 的全部记录");
            hint.setForeground(UiKit.MUTED);
            bar.add(hint);
            panel.add(bar, BorderLayout.NORTH);

            styleTable(eventTable);
            eventTable.getColumnModel().getColumn(0).setPreferredWidth(58);
            eventTable.getColumnModel().getColumn(1).setPreferredWidth(70);
            eventTable.getColumnModel().getColumn(2).setPreferredWidth(125);
            eventTable.getColumnModel().getColumn(3).setPreferredWidth(46);
            eventTable.getColumnModel().getColumn(4).setPreferredWidth(112);
            eventTable.getColumnModel().getColumn(5).setPreferredWidth(52);
            eventTable.getColumnModel().getColumn(6).setPreferredWidth(330);
            eventTable.getColumnModel().getColumn(7).setPreferredWidth(72);
            eventTable.getColumnModel().getColumn(8).setPreferredWidth(50);
            eventTable.getColumnModel().getColumn(9).setPreferredWidth(54);
            eventTable.getColumnModel().getColumn(10).setPreferredWidth(170);

            eventTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int row = eventTable.getSelectedRow();
                        if (row >= 0 && row < visibleEvents.size()) {
                            showIpDetail(visibleEvents.get(row).ip);
                        }
                    }
                }
            });

            panel.add(new JScrollPane(eventTable), BorderLayout.CENTER);

            searchField.getDocument().addDocumentListener(new SimpleDocListener(this::refreshEvents));
            statusFilter.addActionListener(e -> refreshEvents());
            return panel;
        }

        private Component buildIpPanel() {
            JPanel panel = new JPanel(new BorderLayout(0, 8));
            panel.setOpaque(false);
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            bar.setOpaque(false);
            JLabel tip = new JLabel("风险等级依据 WAF 原有拦截结果聚合：高危 = 拦截 ≥3 次或异常分 ≥2 倍阈值，可疑 = 存在拦截或达到阈值；属地取自离线库");
            tip.setForeground(UiKit.MUTED);
            bar.add(tip);
            bar.add(onlyAbnormal);
            JButton export = new JButton("导出 IP 清单 CSV");
            export.addActionListener(e -> exportIps());
            bar.add(export);
            panel.add(bar, BorderLayout.NORTH);

            styleTable(ipTable);
            ipTable.getColumnModel().getColumn(0).setPreferredWidth(145);
            ipTable.getColumnModel().getColumn(1).setPreferredWidth(56);
            ipTable.getColumnModel().getColumn(2).setPreferredWidth(120);
            ipTable.getColumnModel().getColumn(3).setPreferredWidth(60);
            ipTable.getColumnModel().getColumn(4).setPreferredWidth(60);
            ipTable.getColumnModel().getColumn(5).setPreferredWidth(60);
            ipTable.getColumnModel().getColumn(6).setPreferredWidth(58);
            ipTable.getColumnModel().getColumn(7).setPreferredWidth(84);
            ipTable.getColumnModel().getColumn(8).setPreferredWidth(78);
            ipTable.getColumnModel().getColumn(9).setPreferredWidth(300);
            ipTable.getColumnModel().getColumn(10).setPreferredWidth(230);

            ipTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() >= 1) {
                        int row = ipTable.getSelectedRow();
                        if (row >= 0 && row < visibleIps.size()) {
                            showIpDetail(visibleIps.get(row).ip);
                        }
                    }
                }
            });

            onlyAbnormal.addActionListener(e -> refreshIps());
            panel.add(new JScrollPane(ipTable), BorderLayout.CENTER);
            return panel;
        }

        private Component buildDetailPanel() {
            JPanel panel = new JPanel(new BorderLayout(0, 8));
            panel.setOpaque(false);
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel head = new JPanel(new BorderLayout(8, 0));
            head.setOpaque(false);
            JLabel title = new JLabel("尚未选择 IP：可在“访问者 IP”或“防护事件”中单击 / 双击某个 IP");
            title.setFont(UiKit.bold(13));
            title.setForeground(UiKit.MUTED);
            title.setBorder(BorderFactory.createEmptyBorder(0, 4, 6, 0));
            detailTitle = title;
            head.add(title, BorderLayout.CENTER);
            addWhiteBtn = new JButton("加入白名单");
            addWhiteBtn.setEnabled(false);
            addWhiteBtn.addActionListener(e -> onAddToWhitelist());
            head.add(addWhiteBtn, BorderLayout.EAST);
            panel.add(head, BorderLayout.NORTH);

            styleTable(detailTable);
            detailTable.getColumnModel().getColumn(0).setPreferredWidth(58);
            detailTable.getColumnModel().getColumn(1).setPreferredWidth(70);
            detailTable.getColumnModel().getColumn(2).setPreferredWidth(125);
            detailTable.getColumnModel().getColumn(3).setPreferredWidth(46);
            detailTable.getColumnModel().getColumn(4).setPreferredWidth(112);
            detailTable.getColumnModel().getColumn(5).setPreferredWidth(52);
            detailTable.getColumnModel().getColumn(6).setPreferredWidth(330);
            detailTable.getColumnModel().getColumn(7).setPreferredWidth(72);
            detailTable.getColumnModel().getColumn(8).setPreferredWidth(50);
            detailTable.getColumnModel().getColumn(9).setPreferredWidth(54);
            detailTable.getColumnModel().getColumn(10).setPreferredWidth(170);
            panel.add(new JScrollPane(detailTable), BorderLayout.CENTER);
            return panel;
        }

        private JLabel detailTitle;

        private javax.swing.JTextArea configArea;

        private Component buildConfigPanel() {
            JPanel panel = new JPanel(new BorderLayout());
            panel.setOpaque(false);
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            javax.swing.JTextArea area = new javax.swing.JTextArea();
            configArea = area;
            area.setEditable(false);
            area.setFont(new Font("Consolas", Font.PLAIN, 12));
            area.setText(configText());
            area.setCaretPosition(0);
            JButton reload = new JButton("重新读取");
            reload.addActionListener(e -> area.setText(configText()));
            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            bar.setOpaque(false);
            bar.add(reload);
            bar.add(new JLabel("控制台为只读展示，修改配置请编辑 conf/waf.properties 与 rules 下的规则文件"));
            panel.add(bar, BorderLayout.NORTH);
            panel.add(new JScrollPane(area), BorderLayout.CENTER);
            return panel;
        }

        private Component buildStatusBar() {
            JPanel bar = new JPanel(new BorderLayout());
            bar.setBackground(Color.WHITE);
            bar.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(0xE3, 0xE7, 0xEE)),
                    BorderFactory.createEmptyBorder(5, 14, 5, 14)));
            statusBar.setFont(UiKit.plain(11));
            statusBar.setForeground(UiKit.MUTED);
            clockBar.setFont(UiKit.plain(11));
            clockBar.setForeground(UiKit.MUTED);
            bar.add(statusBar, BorderLayout.WEST);
            bar.add(clockBar, BorderLayout.EAST);
            return bar;
        }

        // ---------------- 数据刷新 ----------------

        private void refreshAll() {
            refreshEvents();
            refreshIps();
            refreshKpi();
            refresStatusText();
        }

        private void refreshEvents() {
            String kw = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);
            int mode = statusFilter.getSelectedIndex();
            JScrollPane sp = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, eventTable);
            int scroll = sp == null ? 0 : sp.getVerticalScrollBar().getValue();

            visibleEvents.clear();
            List<WafEvent> all = log.events();
            for (int i = all.size() - 1; i >= 0; i--) {
                WafEvent e = all.get(i);
                if (!matchMode(e, mode)) {
                    continue;
                }
                if (!kw.isEmpty() && !matches(e, kw)) {
                    continue;
                }
                visibleEvents.add(e);
                if (visibleEvents.size() >= 2000) {
                    break;
                }
            }
            eventModel.bind(visibleEvents);
            eventModel.fireTableDataChanged();
            if (sp != null) {
                sp.getVerticalScrollBar().setValue(Math.min(scroll, sp.getVerticalScrollBar().getMaximum()));
            }
        }

        private static boolean matchMode(WafEvent e, int mode) {
            return switch (mode) {
                case 1 -> "BLOCK".equals(e.status) || "BLACKLIST".equals(e.status);
                case 2 -> "BANNED".equals(e.status) || "RATE_LIMIT".equals(e.status);
                case 3 -> "PASS".equals(e.status);
                case 4 -> "UPSTREAM_TIMEOUT".equals(e.status) || "UPSTREAM_UNREACHABLE".equals(e.status);
                default -> true;
            };
        }

        private static boolean matches(WafEvent e, String kw) {
            return e.ip.toLowerCase(Locale.ROOT).contains(kw)
                    || e.pathText().toLowerCase(Locale.ROOT).contains(kw)
                    || e.rules.toLowerCase(Locale.ROOT).contains(kw)
                    || e.ua.toLowerCase(Locale.ROOT).contains(kw)
                    || e.status.toLowerCase(Locale.ROOT).contains(kw)
                    || UiKit.area(e.ip).toLowerCase(Locale.ROOT).contains(kw);
        }

        private void refreshIps() {
            visibleIps.clear();
            int threshold = cfg.inboundThreshold();
            for (WafEventLog.IpAgg a : log.aggs()) {
                if (onlyAbnormal.isSelected() && !a.abnormal()) {
                    continue;
                }
                visibleIps.add(a);
            }
            visibleIps.sort(Comparator
                    .comparingInt((WafEventLog.IpAgg a) -> riskWeight(UiKit.risk(a, threshold))).reversed()
                    .thenComparing(Comparator.comparingInt((WafEventLog.IpAgg a) -> a.blocks).reversed())
                    .thenComparing(Comparator.comparingInt((WafEventLog.IpAgg a) -> a.requests).reversed())
                    .thenComparing(a -> a.ip));
            ipModel.bind(visibleIps, cfg.inboundThreshold());
            ipModel.fireTableDataChanged();
            if (!selectedIp.isEmpty()) {
                updateDetailTitle();
            }
        }

        private static int riskWeight(String risk) {
            return switch (risk) {
                case "高危" -> 3;
                case "可疑" -> 2;
                default -> 1;
            };
        }

        private void refreshKpi() {
            long total = log.total();
            long blocked = log.blocked();
            int threshold = cfg.inboundThreshold();
            int abnormal = 0;
            for (WafEventLog.IpAgg a : log.aggs()) {
                if (!"正常".equals(UiKit.risk(a, threshold))) {
                    abnormal++;
                }
            }
            int ipCount = log.aggs().size();
            kpiTotal.set(String.valueOf(total), "来源 IP " + ipCount + " 个");
            kpiBlock.set(String.valueOf(blocked), blocked == 0 ? "暂无拦截" : "最近 1 条：" + lastBlockText());
            kpiIps.set(String.valueOf(abnormal), abnormal == 0 ? "全部来源正常" : "高危 " + countRisk("高危", threshold)
                    + " · 可疑 " + countRisk("可疑", threshold));
            double rate = total == 0 ? 0 : blocked * 100.0 / total;
            kpiRate.set(String.format(Locale.ROOT, "%.1f%%", rate), "阈值 " + threshold + " 分");
        }

        private int countRisk(String risk, int threshold) {
            int n = 0;
            for (WafEventLog.IpAgg a : log.aggs()) {
                if (risk.equals(UiKit.risk(a, threshold))) {
                    n++;
                }
            }
            return n;
        }

        private String lastBlockText() {
            List<WafEvent> all = log.events();
            for (int i = all.size() - 1; i >= 0; i--) {
                if (all.get(i).blocked()) {
                    WafEvent e = all.get(i);
                    return e.ip + " · " + e.level() + " · " + UiKit.truncate(e.uri, 22);
                }
            }
            return "-";
        }

        private void refresStatusText() {
            String err = log.lastError();
            String msg = "日志：" + cfg.logFile()
                    + "   |   已读事件 " + log.total()
                    + "   |   跳过 " + log.skipped() + " 行";
            if (!err.isEmpty()) {
                msg += "   |   读取异常：" + err;
                statusBar.setForeground(UiKit.DANGER);
            } else {
                statusBar.setForeground(UiKit.MUTED);
            }
            statusBar.setText(msg);
        }

        // ---------------- 服务状态 ----------------

        private final AtomicInteger probeBusy = new AtomicInteger();

        private void probeService() {
            if (probeBusy.getAndIncrement() > 0) {
                return;
            }
            Thread t = new Thread(() -> {
                IisSnapshot snap;
                Map<Integer, Integer> plan;
                List<String> lines = new ArrayList<>();
                boolean anyUp = false;
                boolean allUp = true;
                try {
                    snap = IisMonitor.peek(cfg.iisConfigPath().orElse(null));
                    plan = cfg.iisAuto()
                            ? IisFrontPorts.plan(snap.httpPorts(), cfg.listenPort(), cfg.iisFrontMap())
                            : Map.of();
                    if (plan.isEmpty()) {
                        boolean up = IisConfigReader.probe(cfg.listenPort());
                        anyUp = up;
                        allUp = up;
                        lines.add("固定监听 " + cfg.listenPort() + (up ? " 正常" : " 未监听"));
                    } else {
                        for (Map.Entry<Integer, Integer> e : plan.entrySet()) {
                            boolean up = IisConfigReader.probe(e.getValue());
                            anyUp |= up;
                            allUp &= up;
                            lines.add("IIS 端口 " + e.getKey() + " → 防护端口 " + e.getValue()
                                    + (up ? " 正常" : " 未监听"));
                        }
                    }
                } catch (RuntimeException ex) {
                    snap = IisSnapshot.empty("读取 IIS 配置失败：" + ex.getMessage());
                    plan = Map.of();
                    lines.add("读取 IIS 配置失败：" + ex.getMessage());
                } finally {
                    probeBusy.set(0);
                }
                IisSnapshot fsnap = snap;
                Map<Integer, Integer> fplan = plan;
                boolean fAny = anyUp;
                boolean fAll = allUp;
                List<String> flines = lines;
                SwingUtilities.invokeLater(() -> applyServiceStatus(fsnap, fplan, fAny, fAll, flines));
            }, "waf-console-probe");
            t.setDaemon(true);
            t.start();
        }

        /** 依据 IIS 站点端口刷新顶部状态徽标与副标题。 */
        private void applyServiceStatus(IisSnapshot snap, Map<Integer, Integer> plan,
                                        boolean anyUp, boolean allUp, List<String> lines) {
            iisSnapshot = snap;
            iisPlan = plan;
            String target = plan.isEmpty()
                    ? "固定监听 " + cfg.listenHost() + ":" + cfg.listenPort()
                    : snap.shortSummary();
            if (anyUp) {
                statusPill.setText((allUp ? "● 防护运行中 · " : "● 部分监听正常 · ") + target);
                statusPill.setBackground(new Color(0xE6, 0xF6, 0xEC));
                statusPill.setForeground(new Color(0x0E, 0x7A, 0x45));
            } else {
                statusPill.setText("● 未检测到监听 · " + target);
                statusPill.setBackground(new Color(0xFD, 0xEC, 0xEC));
                statusPill.setForeground(new Color(0xB4, 0x23, 0x23));
            }
            statusPill.setToolTipText("<html>" + String.join("<br>", lines)
                    + "<br>IIS 站点 " + snap.sites().size() + " 个 · " + snap.source() + "</html>");
            if (specLabel != null) {
                specLabel.setText("v" + VERSION + " · 防护对象 " + target
                        + " · 上游 " + cfg.upstreamBase()
                        + " · 入站阈值 " + cfg.inboundThreshold()
                        + " · 日志 " + cfg.logFile().getFileName());
            }
            if (configArea != null) {
                configArea.setText(configText());
            }
        }

        // ---------------- IP 详情 ----------------

        private void showIpDetail(String ip) {
            selectedIp = ip;
            addWhiteBtn.setEnabled(!selectedIp.isEmpty());
            detailEvents.clear();
            List<WafEvent> all = log.events();
            for (int i = all.size() - 1; i >= 0; i--) {
                if (all.get(i).ip.equals(ip)) {
                    detailEvents.add(all.get(i));
                }
            }
            detailModel.bind(detailEvents);
            detailModel.fireTableDataChanged();
            updateDetailTitle();
            tabs.setSelectedIndex(2);
        }

        private void updateDetailTitle() {
            WafEventLog.IpAgg a = log.agg(selectedIp);
            if (a == null) {
                detailTitle.setText("IP " + selectedIp + " · 暂无记录");
                detailTitle.setForeground(UiKit.MUTED);
                return;
            }
            int threshold = cfg.inboundThreshold();
            String risk = UiKit.risk(a, threshold);
            detailTitle.setText("IP " + a.ip + "  [" + UiKit.scope(a.ip) + " · " + UiKit.areaDetail(a.ip) + "]   风险：" + risk
                    + "   请求 " + a.requests + " 次 / 拦截 " + a.blocks + " 次   最高异常分 " + a.maxScore
                    + "   命中规则 " + a.rules.size() + " 条   最近访问 " + a.lastTimeText()
                    + (a.lastUa.isEmpty() ? "" : "   UA：" + UiKit.truncate(a.lastUa, 46)));
            detailTitle.setForeground(UiKit.riskColor(risk));
        }

        // ---------------- 白名单管理口令 ----------------

        /** 新安装或从旧版本升级后，首次打开控制台前要求设置白名单管理口令。 */
        private void ensureFirstRunPassword() {
            if (!PasscodeGuard.hasPassword(securityFile)) {
                JOptionPane.showMessageDialog(this,
                        "检测到新安装或从旧版本升级的 Chingtsi WAF 1.1.0。\n"
                                + "首次运行前，请先设置白名单管理口令；\n"
                                + "设置后，向 IP 白名单添加条目都需要输入该口令。",
                        "设置白名单管理口令", JOptionPane.INFORMATION_MESSAGE);
                while (!PasscodeGuard.hasPassword(securityFile)) {
                    if (!PasscodeDialog.ensureSetup(this, securityFile)) {
                        int choice = JOptionPane.showConfirmDialog(this,
                                "不设置口令将无法向白名单添加 IP，相关功能将被锁定。是否再次设置？",
                                "白名单管理口令未设置", JOptionPane.YES_NO_OPTION,
                                JOptionPane.WARNING_MESSAGE);
                        if (choice != JOptionPane.YES_OPTION) {
                            dispose();
                            System.exit(0);
                        }
                    }
                }
            }
        }

        private void managePasscode() {
            if (!PasscodeGuard.hasPassword(securityFile)) {
                if (PasscodeDialog.ensureSetup(this, securityFile)) {
                    JOptionPane.showMessageDialog(this, "白名单管理口令已保存至 " + securityFile, "已设置",
                            JOptionPane.INFORMATION_MESSAGE);
                }
                return;
            }
            Object[] options = {"验证口令", "修改口令", "取消"};
            int c = JOptionPane.showOptionDialog(this,
                    "白名单管理口令已设置。验证口令后，才能向 IP 白名单添加条目。",
                    "白名单管理口令", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[0]);
            if (c == 0) {
                String pw = PasscodeDialog.verify(this, securityFile);
                if (pw != null) {
                    JOptionPane.showMessageDialog(this, "口令验证通过。", "验证成功",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            } else if (c == 1) {
                if (PasscodeDialog.change(this, securityFile)) {
                    JOptionPane.showMessageDialog(this, "白名单管理口令已更新。", "已更新",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }

        /** 验证口令后，将当前选中 IP 写入白名单文件（白名单文件由运行中的 WAF 热加载）。 */
        private void onAddToWhitelist() {
            if (selectedIp == null || selectedIp.isEmpty()) {
                return;
            }
            String pw = PasscodeDialog.verify(this, securityFile);
            if (pw == null) {
                return; // 用户取消
            }
            Path wl = cfg.whitelistFile();
            try {
                InetAddress.getByName(selectedIp); // 校验合法 IP 地址
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "无效的 IP 地址：" + selectedIp, "添加失败",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                boolean already = false;
                if (Files.isRegularFile(wl)) {
                    for (String line : Files.readAllLines(wl, StandardCharsets.UTF_8)) {
                        String t = line.trim();
                        int h = t.indexOf('#');
                        if (h >= 0) {
                            t = t.substring(0, h).trim();
                        }
                        if (!t.isEmpty() && t.equalsIgnoreCase(selectedIp)) {
                            already = true;
                            break;
                        }
                    }
                }
                if (already) {
                    JOptionPane.showMessageDialog(this, selectedIp + " 已在白名单中。", "提示",
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                Files.createDirectories(wl.getParent());
                String stamp = LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
                String entry = "\n# 白名单添加：" + selectedIp + " （控制台添加，" + stamp + "）\n" + selectedIp + "\n";
                Files.writeString(wl, entry, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND);
                refreshIps();
                updateDetailTitle();
                JOptionPane.showMessageDialog(this,
                        selectedIp + " 已加入白名单。该 IP 的请求将跳过全部检测（规则、限流、黑名单），"
                                + " 直接代理到上游；白名单文件已热加载，无需重启 WAF。",
                        "已加入白名单", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "写入白名单失败：" + ex.getMessage(), "添加失败",
                        JOptionPane.ERROR_MESSAGE);
            }
        }

        // ---------------- 导出 ----------------

        private void exportEvents() {
            if (visibleEvents.isEmpty()) {
                JOptionPane.showMessageDialog(this, "当前没有可导出的记录。", "导出", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            Path target = chooseFile("waf-events-" + stamp() + ".csv");
            if (target == null) {
                return;
            }
            StringBuilder sb = new StringBuilder("\uFEFF");
            sb.append("时间,IP,归属,属地,方法,路径,判定,状态码,异常分,耗时ms,命中规则,User-Agent\n");
            for (WafEvent e : visibleEvents) {
                sb.append(csv(e.ts)).append(',')
                        .append(csv(e.ip)).append(',')
                        .append(csv(UiKit.scope(e.ip))).append(',')
                        .append(csv(UiKit.area(e.ip))).append(',')
                        .append(csv(e.method)).append(',')
                        .append(csv(e.pathText())).append(',')
                        .append(csv(e.level())).append(',')
                        .append(e.code).append(',')
                        .append(e.score).append(',')
                        .append(e.elapsed).append(',')
                        .append(csv(e.rules)).append(',')
                        .append(csv(e.ua)).append('\n');
            }
            writeCsv(target, sb);
        }

        private void exportIps() {
            if (visibleIps.isEmpty()) {
                JOptionPane.showMessageDialog(this, "当前没有可导出的记录。", "导出", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            Path target = chooseFile("waf-ips-" + stamp() + ".csv");
            if (target == null) {
                return;
            }
            int threshold = cfg.inboundThreshold();
            StringBuilder sb = new StringBuilder("\uFEFF");
            sb.append("IP,归属,属地,请求数,拦截数,拦截率,最高异常分,风险等级,命中规则数,最近访问,最近路径,最近User-Agent\n");
            for (WafEventLog.IpAgg a : visibleIps) {
                double rate = a.requests == 0 ? 0 : a.blocks * 100.0 / a.requests;
                sb.append(csv(a.ip)).append(',')
                        .append(csv(UiKit.scope(a.ip))).append(',')
                        .append(csv(UiKit.area(a.ip))).append(',')
                        .append(a.requests).append(',')
                        .append(a.blocks).append(',')
                        .append(String.format(Locale.ROOT, "%.1f%%", rate)).append(',')
                        .append(a.maxScore).append(',')
                        .append(csv(UiKit.risk(a, threshold))).append(',')
                        .append(a.rules.size()).append(',')
                        .append(csv(a.lastTimeText())).append(',')
                        .append(csv(a.lastPath)).append(',')
                        .append(csv(a.lastUa)).append('\n');
            }
            writeCsv(target, sb);
        }

        private void writeCsv(Path target, StringBuilder sb) {
            try {
                Files.writeString(target, sb.toString(), StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                JOptionPane.showMessageDialog(this, "已导出：\n" + target, "导出成功",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "导出失败：" + ex.getMessage(), "导出失败",
                        JOptionPane.ERROR_MESSAGE);
            }
        }

        private Path chooseFile(String name) {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("选择导出位置");
            fc.setSelectedFile(home.resolve(name).toFile());
            if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
                return null;
            }
            return fc.getSelectedFile().toPath();
        }

        private static String stamp() {
            return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        }

        private static String csv(String s) {
            if (s == null) {
                return "";
            }
            String v = s.replace("\r", " ").replace("\n", " ");
            if (v.contains(",") || v.contains("\"")) {
                return '"' + v.replace("\"", "\"\"") + '"';
            }
            return v;
        }

        // ---------------- 杂项 ----------------

        private void styleTable(JTable t) {
            t.setRowHeight(28);
            t.setFont(UiKit.plain(12));
            t.setFillsViewportHeight(true);
            t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            t.setShowGrid(false);
            t.setIntercellSpacing(new Dimension(0, 0));
            t.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
            JTableHeader h = t.getTableHeader();
            h.setFont(UiKit.bold(12));
            h.setReorderingAllowed(false);
            h.setBackground(new Color(0xF6, 0xF8, 0xFB));
            t.setDefaultRenderer(Object.class, new UiKit.EventRenderer());
            t.setDefaultRenderer(Number.class, new UiKit.PlainRenderer());
        }

        /** 支持命令行直达：-Dwaf.tab=1..4 选中标签页，-Dwaf.ip=1.2.3.4 直接查看该 IP。 */
        private void applyStartupHint() {
            String tab = System.getProperty("waf.tab");
            if (tab != null) {
                try {
                    int idx = Integer.parseInt(tab.trim()) - 1;
                    tabs.setSelectedIndex(Math.max(0, Math.min(tabs.getTabCount() - 1, idx)));
                } catch (NumberFormatException ignored) {
                    // 参数非法则保持默认页
                }
            }
            String ip = System.getProperty("waf.ip");
            if (ip != null && !ip.isBlank()) {
                showIpDetail(ip.trim());
            }
        }

        private void installTabShortcuts(JPanel root) {
            javax.swing.InputMap im = root.getInputMap(JPanel.WHEN_IN_FOCUSED_WINDOW);
            javax.swing.ActionMap am = root.getActionMap();
            for (int i = 0; i < 4; i++) {
                final int idx = i;
                javax.swing.KeyStroke ks = javax.swing.KeyStroke.getKeyStroke(
                        java.awt.event.KeyEvent.VK_1 + i, java.awt.event.InputEvent.ALT_DOWN_MASK);
                String key = "switchTab" + i;
                im.put(ks, key);
                am.put(key, new javax.swing.AbstractAction() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        tabs.setSelectedIndex(idx);
                    }
                });
            }
        }

        private void applyIcon() {
            try {
                List<Image> images = UiKit.logoImages();
                if (!images.isEmpty()) {
                    setIconImages(images);
                }
            } catch (RuntimeException ignored) {
                // 无图标资源时使用默认图标
            }
        }

        private void openFolder(Path dir) {
            try {
                if (dir != null && Files.isDirectory(dir)) {
                    java.awt.Desktop.getDesktop().open(dir.toFile());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "无法打开目录：" + dir, "提示", JOptionPane.WARNING_MESSAGE);
            }
        }

        private String configText() {
            StringBuilder sb = new StringBuilder();
            sb.append("运行根目录 : ").append(home).append('\n');
            sb.append("配置目录   : ").append(home.resolve("conf")).append('\n');
            sb.append("规则目录   : ").append(cfg.ruleDir()).append('\n');
            sb.append("日志文件   : ").append(cfg.logFile()).append('\n');
            sb.append('\n');
            sb.append("监听地址   : ").append(cfg.listenHost()).append(':').append(cfg.listenPort()).append('\n');
            sb.append("上游地址   : ").append(cfg.upstreamBase()).append('\n');
            sb.append("工作线程   : ").append(cfg.workerThreads()).append('\n');
            sb.append("入站阈值   : ").append(cfg.inboundThreshold()).append('\n');
            sb.append("出站阈值   : ").append(cfg.outboundThreshold()).append('\n');
            sb.append("单请求上限 : ").append(cfg.maxBodyBytes()).append(" B\n");
            sb.append("限流       : 窗口 ").append(cfg.rateWindowSeconds()).append("s / 上限 ")
                    .append(cfg.rateLimit()).append(" 次 / 封禁 ").append(cfg.banSeconds()).append("s\n");
            sb.append("可信 CF    : ").append(cfg.trustCfConnectingIp()).append('\n');
            sb.append('\n');
            sb.append("---- 防护对象（自动检测 IIS）----\n");
            sb.append("检测方式   : ").append(cfg.iisAuto() ? "自动检查 IIS 站点绑定端口" : "已关闭，使用固定监听").append('\n');
            sb.append(iisSnapshot.detailText()).append('\n');
            sb.append("前置端口   : ").append(iisPlan.isEmpty()
                    ? "固定 " + cfg.listenHost() + ":" + cfg.listenPort()
                    : IisFrontPorts.describe(iisPlan)).append('\n');
            sb.append('\n');
            sb.append("---- 规则文件 ----\n");
            try (var s = Files.list(cfg.ruleDir())) {
                s.filter(Files::isRegularFile).sorted().forEach(p -> {
                    long lines = 0;
                    try {
                        lines = Files.readAllLines(p).stream()
                                .filter(l -> l.strip().toLowerCase(Locale.ROOT).startsWith("secrule")).count();
                    } catch (IOException ignored) {
                        // 读取失败则不显示条数
                    }
                    sb.append(String.format(Locale.ROOT, "%-24s %4d 条规则%n", p.getFileName(), lines));
                });
            } catch (Exception e) {
                sb.append("（无法读取规则目录）\n");
            }
            sb.append('\n');
            sb.append("---- IP 名单 ----\n");
            sb.append("白名单 ").append(countLines(cfg.whitelistFile())).append(" 条  (")
                    .append(cfg.whitelistFile()).append(")\n");
            sb.append("黑名单 ").append(countLines(cfg.blacklistFile())).append(" 条  (")
                    .append(cfg.blacklistFile()).append(")\n");
            return sb.toString();
        }

        private static long countLines(Path p) {
            try {
                return Files.readAllLines(p).stream()
                        .map(String::strip)
                        .filter(l -> !l.isEmpty() && !l.startsWith("#")).count();
            } catch (IOException e) {
                return 0;
            }
        }
    }

    private static WafConfig loadConfig(Path home) {
        try {
            return WafConfig.load(home.resolve("conf").resolve("waf.properties"));
        } catch (RuntimeException e) {
            System.out.println("[WARN ] 控制台读取配置失败，使用默认值：" + e.getMessage());
            return WafConfig.load(Path.of("__missing__").resolve("conf").resolve("waf.properties"));
        }
    }

    // ==================================================================
    //  表格模型
    // ==================================================================

    private static final String[] EVENT_COLUMNS = {
            "序号", "时间", "来源 IP", "归属", "属地", "方法", "路径", "判定", "HTTP", "异常分", "命中规则"
    };

    static final class EventModel extends AbstractTableModel implements UiKit.EventTableModel {

        private List<WafEvent> data = List.of();

        void bind(List<WafEvent> list) {
            this.data = list;
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return EVENT_COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return EVENT_COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 9 ? Integer.class : Object.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            WafEvent e = data.get(row);
            return switch (column) {
                case 0 -> (data.size() - row);
                case 1 -> e.timeText;
                case 2 -> e.ip;
                case 3 -> UiKit.scope(e.ip);
                case 4 -> UiKit.area(e.ip);
                case 5 -> e.method;
                case 6 -> UiKit.truncate(e.pathText(), 120);
                case 7 -> e.level();
                case 8 -> e.code;
                case 9 -> e.score;
                default -> e.ruleSummary();
            };
        }

        @Override
        public String statusAt(int modelRow) {
            return modelRow >= 0 && modelRow < data.size() ? data.get(modelRow).status : "PASS";
        }
    }

    private static final String[] IP_COLUMNS = {
            "来源 IP", "归属", "属地", "请求数", "拦截数", "拦截率", "最高分", "风险等级", "最近访问", "最近路径", "最近 User-Agent"
    };

    static final class IpModel extends AbstractTableModel implements UiKit.EventTableModel {

        private List<WafEventLog.IpAgg> data = List.of();
        private int threshold = 5;

        void bind(List<WafEventLog.IpAgg> list, int threshold) {
            this.data = list;
            this.threshold = threshold;
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return IP_COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return IP_COLUMNS[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            WafEventLog.IpAgg a = data.get(row);
            return switch (column) {
                case 0 -> a.ip;
                case 1 -> UiKit.scope(a.ip);
                case 2 -> UiKit.area(a.ip);
                case 3 -> a.requests;
                case 4 -> a.blocks;
                case 5 -> String.format(Locale.ROOT, "%.0f%%",
                        a.requests == 0 ? 0 : a.blocks * 100.0 / a.requests);
                case 6 -> a.maxScore;
                case 7 -> UiKit.risk(a, threshold);
                case 8 -> a.lastTimeText();
                case 9 -> UiKit.truncate(a.lastPath, 90);
                default -> UiKit.truncate(a.lastUa, 70);
            };
        }

        @Override
        public String statusAt(int modelRow) {
            return modelRow >= 0 && modelRow < data.size() && data.get(modelRow).blocks > 0 ? "BLOCK" : "PASS";
        }
    }

    /** 文本变化监听，避免匿名类重复实现三个方法。 */
    static final class SimpleDocListener implements javax.swing.event.DocumentListener {

        private final Runnable onChange;

        SimpleDocListener(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }
    }
}
