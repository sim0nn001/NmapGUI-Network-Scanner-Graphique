#include <gtk/gtk.h>
#include <string>
#include <vector>
#include <sstream>
#include <regex>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <memory>
#include <array>
#include <map>
#include <functional>
#include <algorithm>

// ─── Data structures ──────────────────────────────────────────────────────────

struct PortInfo {
    int         port;
    std::string protocol;
    std::string state;
    std::string service;
    std::string version;
};

struct HostInfo {
    std::string ip;
    std::string hostname;
    std::string status;       // up / down
    std::string os_guess;
    std::string mac;
    std::string vendor;
    std::string latency;
    std::vector<PortInfo> ports;
};

// ─── Global UI state ──────────────────────────────────────────────────────────

struct AppWidgets {
    GtkWidget* window;
    GtkWidget* target_entry;
    GtkWidget* scan_type_combo;
    GtkWidget* timing_combo;
    GtkWidget* ports_entry;
    GtkWidget* scan_btn;
    GtkWidget* stop_btn;
    GtkWidget* progress_bar;
    GtkWidget* status_label;
    GtkWidget* host_tree;
    GtkListStore* host_store;
    GtkWidget* port_tree;
    GtkListStore* port_store;
    GtkWidget* raw_output;
    GtkTextBuffer* raw_buffer;
    GtkWidget* summary_label;
    GtkWidget* spinner;
    GtkWidget* host_count_label;
    GtkWidget* port_count_label;
};

static AppWidgets app;
static std::atomic<bool> scan_running{false};
static std::mutex result_mutex;
static std::vector<HostInfo> scan_results;
static std::string raw_nmap_output;

// ─── CSS Theme ────────────────────────────────────────────────────────────────

static const char* CSS_THEME = R"css(
* {
    font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
}

window {
    background-color: #0D1117;
    color: #C9D1D9;
}

.header-bar {
    background: linear-gradient(90deg, #0D1117 0%, #161B22 100%);
    border-bottom: 1px solid #00FFCC22;
    padding: 8px 16px;
}

.title-label {
    color: #00FFCC;
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 2px;
}

.subtitle-label {
    color: #58A6FF;
    font-size: 11px;
    letter-spacing: 1px;
}

.panel {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 12px;
}

.panel-title {
    color: #00FFCC;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 2px;
    margin-bottom: 8px;
}

entry {
    background-color: #0D1117;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 6px 10px;
    caret-color: #00FFCC;
}

entry:focus {
    border-color: #00FFCC;
    box-shadow: 0 0 0 2px #00FFCC22;
}

combobox button {
    background-color: #0D1117;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 4px 8px;
}

combobox button:hover {
    border-color: #00FFCC;
    background-color: #161B22;
}

.btn-scan {
    background: linear-gradient(135deg, #00FFCC, #00CC99);
    color: #0D1117;
    border: none;
    border-radius: 4px;
    padding: 8px 20px;
    font-weight: bold;
    font-size: 12px;
    letter-spacing: 1px;
}

.btn-scan:hover {
    background: linear-gradient(135deg, #33FFDD, #00FFCC);
}

.btn-scan:active {
    background: #00AA88;
}

.btn-scan:disabled {
    background: #1C2128;
    color: #484F58;
}

.btn-stop {
    background-color: transparent;
    color: #FF6B6B;
    border: 1px solid #FF6B6B;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
    font-size: 12px;
}

.btn-stop:hover {
    background-color: #FF6B6B22;
}

.btn-stop:disabled {
    color: #484F58;
    border-color: #30363D;
}

treeview {
    background-color: #0D1117;
    color: #C9D1D9;
    border: none;
    font-size: 12px;
}

treeview:selected {
    background-color: #00FFCC22;
    color: #00FFCC;
}

treeview header button {
    background-color: #161B22;
    color: #58A6FF;
    border-bottom: 1px solid #30363D;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    padding: 6px 8px;
}

scrolledwindow {
    border: 1px solid #30363D;
    border-radius: 4px;
}

.status-up {
    color: #3FB950;
    font-weight: bold;
}

.status-down {
    color: #FF6B6B;
}

.port-open {
    color: #3FB950;
}

.port-filtered {
    color: #E3B341;
}

.port-closed {
    color: #FF6B6B;
}

progressbar {
    border-radius: 2px;
}

progressbar trough {
    background-color: #21262D;
    border: 1px solid #30363D;
    border-radius: 2px;
    min-height: 6px;
}

progressbar progress {
    background: linear-gradient(90deg, #00FFCC, #58A6FF);
    border-radius: 2px;
    min-height: 6px;
}

.status-bar {
    background-color: #0D1117;
    border-top: 1px solid #21262D;
    padding: 4px 12px;
    font-size: 11px;
    color: #58A6FF;
}

.raw-output {
    background-color: #0D1117;
    color: #79C0FF;
    font-size: 11px;
    padding: 8px;
}

.counter-badge {
    background-color: #00FFCC22;
    color: #00FFCC;
    border: 1px solid #00FFCC44;
    border-radius: 10px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: bold;
}

.info-label {
    color: #8B949E;
    font-size: 11px;
}

label {
    color: #C9D1D9;
}

notebook {
    background-color: #0D1117;
}

notebook header {
    background-color: #161B22;
    border-bottom: 1px solid #30363D;
}

notebook header tabs tab {
    background-color: transparent;
    color: #8B949E;
    padding: 8px 16px;
    border: none;
    font-size: 11px;
    letter-spacing: 1px;
}

notebook header tabs tab:checked {
    color: #00FFCC;
    border-bottom: 2px solid #00FFCC;
}

separator {
    background-color: #21262D;
    min-height: 1px;
}

spinner {
    color: #00FFCC;
}
)css";

// ─── Nmap parsing ─────────────────────────────────────────────────────────────

std::vector<HostInfo> parse_nmap_output(const std::string& output) {
    std::vector<HostInfo> hosts;
    HostInfo current;
    bool in_host = false;

    std::istringstream ss(output);
    std::string line;

    std::regex re_report(R"(Nmap scan report for (.+))");
    std::regex re_status(R"(Host is (\w+))");
    std::regex re_latency(R"(Host is up \(([0-9.]+)s latency\))");
    std::regex re_port(R"((\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*))");
    std::regex re_os(R"(OS details: (.+))");
    std::regex re_mac(R"(MAC Address: ([0-9A-F:]+) \((.+)\))");
    std::regex re_hostname(R"(Nmap scan report for (\S+) \(([0-9.]+)\))");

    while (std::getline(ss, line)) {
        std::smatch m;

        // New host block
        if (std::regex_search(line, m, re_hostname)) {
            if (in_host && !current.ip.empty()) hosts.push_back(current);
            current = HostInfo{};
            in_host = true;
            current.hostname = m[1];
            current.ip = m[2];
            continue;
        }
        if (std::regex_search(line, m, re_report)) {
            if (in_host && !current.ip.empty()) hosts.push_back(current);
            current = HostInfo{};
            in_host = true;
            std::string target = m[1];
            // Could be IP or hostname
            std::regex ip_re(R"(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$)");
            if (std::regex_match(target, ip_re))
                current.ip = target;
            else
                current.hostname = target;
            continue;
        }

        if (!in_host) continue;

        if (std::regex_search(line, m, re_latency)) {
            current.status = "up";
            current.latency = m[1].str() + "s";
        } else if (std::regex_search(line, m, re_status)) {
            current.status = m[1];
        }

        if (std::regex_search(line, m, re_port)) {
            PortInfo p;
            p.port     = std::stoi(m[1]);
            p.protocol = m[2];
            p.state    = m[3];
            p.service  = m[4];
            p.version  = m[5];
            current.ports.push_back(p);
        }

        if (std::regex_search(line, m, re_os))  current.os_guess = m[1];
        if (std::regex_search(line, m, re_mac)) {
            current.mac    = m[1];
            current.vendor = m[2];
        }
    }

    if (in_host && !current.ip.empty()) hosts.push_back(current);
    else if (in_host && !current.hostname.empty()) hosts.push_back(current);

    return hosts;
}

// ─── Nmap runner ──────────────────────────────────────────────────────────────

std::string exec_command(const std::string& cmd) {
    std::string result;
    std::array<char, 512> buf;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "ERROR: popen failed";
    while (fgets(buf.data(), buf.size(), pipe.get()) != nullptr)
        result += buf.data();
    return result;
}

// ─── GTK thread-safe callbacks ────────────────────────────────────────────────

struct ScanDoneData {
    std::vector<HostInfo> hosts;
    std::string raw;
};

static gboolean on_scan_done_main_thread(gpointer data) {
    auto* d = static_cast<ScanDoneData*>(data);

    // Update raw output
    gtk_text_buffer_set_text(app.raw_buffer, d->raw.c_str(), -1);

    // Clear host store
    gtk_list_store_clear(app.host_store);
    gtk_list_store_clear(app.port_store);

    int total_ports = 0;
    for (auto& h : d->hosts) {
        GtkTreeIter iter;
        gtk_list_store_append(app.host_store, &iter);
        std::string display_ip = h.ip.empty() ? h.hostname : h.ip;
        std::string display_hn = h.hostname.empty() ? "—" : h.hostname;
        std::string status_icon = (h.status == "up") ? "● " : "○ ";
        gtk_list_store_set(app.host_store, &iter,
            0, display_ip.c_str(),
            1, display_hn.c_str(),
            2, (status_icon + h.status).c_str(),
            3, h.os_guess.empty() ? "—" : h.os_guess.c_str(),
            4, h.mac.empty() ? "—" : h.mac.c_str(),
            5, h.vendor.empty() ? "—" : h.vendor.c_str(),
            6, h.latency.empty() ? "—" : h.latency.c_str(),
            7, (int)h.ports.size(),
            -1);
        total_ports += h.ports.size();
    }

    // Summary
    char summary[256];
    snprintf(summary, sizeof(summary), "%d hôte(s) découvert(s)  ·  %d port(s) analysé(s)",
             (int)d->hosts.size(), total_ports);
    gtk_label_set_text(GTK_LABEL(app.summary_label), summary);

    char hc[64]; snprintf(hc, sizeof(hc), "%d", (int)d->hosts.size());
    gtk_label_set_text(GTK_LABEL(app.host_count_label), hc);
    char pc[64]; snprintf(pc, sizeof(pc), "%d", total_ports);
    gtk_label_set_text(GTK_LABEL(app.port_count_label), pc);

    // Save results globally
    {
        std::lock_guard<std::mutex> lock(result_mutex);
        scan_results = d->hosts;
    }

    // UI state
    gtk_widget_set_sensitive(app.scan_btn, TRUE);
    gtk_widget_set_sensitive(app.stop_btn, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), 1.0);
    gtk_spinner_stop(GTK_SPINNER(app.spinner));
    gtk_label_set_text(GTK_LABEL(app.status_label), "Scan terminé.");
    scan_running = false;

    delete d;
    return G_SOURCE_REMOVE;
}

static gboolean on_progress_update(gpointer data) {
    if (!scan_running) return G_SOURCE_REMOVE;
    double val = gtk_progress_bar_get_fraction(GTK_PROGRESS_BAR(app.progress_bar));
    val = std::min(val + 0.015, 0.95);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), val);
    return G_SOURCE_CONTINUE;
}

// ─── Host selection → port table ──────────────────────────────────────────────

static void on_host_selected(GtkTreeSelection* sel, gpointer) {
    gtk_list_store_clear(app.port_store);

    GtkTreeIter iter;
    GtkTreeModel* model;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) return;

    gchar* ip_str = nullptr;
    gtk_tree_model_get(model, &iter, 0, &ip_str, -1);
    if (!ip_str) return;

    std::string sel_ip = ip_str;
    g_free(ip_str);

    std::lock_guard<std::mutex> lock(result_mutex);
    for (auto& h : scan_results) {
        std::string disp = h.ip.empty() ? h.hostname : h.ip;
        if (disp == sel_ip) {
            for (auto& p : h.ports) {
                GtkTreeIter piter;
                gtk_list_store_append(app.port_store, &piter);
                gtk_list_store_set(app.port_store, &piter,
                    0, p.port,
                    1, p.protocol.c_str(),
                    2, p.state.c_str(),
                    3, p.service.c_str(),
                    4, p.version.empty() ? "—" : p.version.c_str(),
                    -1);
            }
            break;
        }
    }
}

// ─── Scan thread ──────────────────────────────────────────────────────────────

struct ScanParams {
    std::string target;
    std::string scan_type;
    std::string timing;
    std::string ports;
};

static void scan_thread(ScanParams params) {
    // Build nmap command
    std::string cmd = "nmap ";

    // Scan type flags
    if      (params.scan_type == "Ping Sweep")        cmd += "-sn ";
    else if (params.scan_type == "SYN Scan")          cmd += "-sS ";
    else if (params.scan_type == "TCP Connect")       cmd += "-sT ";
    else if (params.scan_type == "UDP Scan")          cmd += "-sU ";
    else if (params.scan_type == "OS Detection")      cmd += "-O --osscan-guess ";
    else if (params.scan_type == "Service Version")   cmd += "-sV ";
    else if (params.scan_type == "Agressif (-A)")     cmd += "-A ";
    else if (params.scan_type == "Scan rapide")       cmd += "-F ";

    // Timing
    cmd += params.timing + " ";

    // Ports
    if (!params.ports.empty() && params.scan_type != "Ping Sweep")
        cmd += "-p " + params.ports + " ";

    cmd += params.target + " 2>&1";

    // Update status
    g_idle_add([](gpointer d) -> gboolean {
        gtk_label_set_text(GTK_LABEL(app.status_label),
            "Exécution de nmap...");
        return G_SOURCE_REMOVE;
    }, nullptr);

    std::string output = exec_command(cmd);

    auto* done = new ScanDoneData{parse_nmap_output(output), output};
    g_idle_add(on_scan_done_main_thread, done);
}

// ─── Scan button callback ─────────────────────────────────────────────────────

static void on_scan_clicked(GtkWidget*, gpointer) {
    if (scan_running) return;

    const gchar* target = gtk_entry_get_text(GTK_ENTRY(app.target_entry));
    if (!target || strlen(target) == 0) {
        GtkWidget* dlg = gtk_message_dialog_new(
            GTK_WINDOW(app.window),
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_WARNING,
            GTK_BUTTONS_OK,
            "Veuillez entrer une cible (IP, plage CIDR, hostname).");
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    // Get scan type
    gchar* scan_type = gtk_combo_box_text_get_active_text(
        GTK_COMBO_BOX_TEXT(app.scan_type_combo));
    gchar* timing_raw = gtk_combo_box_text_get_active_text(
        GTK_COMBO_BOX_TEXT(app.timing_combo));
    const gchar* ports = gtk_entry_get_text(GTK_ENTRY(app.ports_entry));

    // Extract timing flag (e.g. "T3 - Normal" → "-T3")
    std::string timing_flag = "-T3";
    if (timing_raw) {
        std::string ts = timing_raw;
        if      (ts.find("T0") != std::string::npos) timing_flag = "-T0";
        else if (ts.find("T1") != std::string::npos) timing_flag = "-T1";
        else if (ts.find("T2") != std::string::npos) timing_flag = "-T2";
        else if (ts.find("T3") != std::string::npos) timing_flag = "-T3";
        else if (ts.find("T4") != std::string::npos) timing_flag = "-T4";
        else if (ts.find("T5") != std::string::npos) timing_flag = "-T5";
        g_free(timing_raw);
    }

    ScanParams params{
        std::string(target),
        scan_type ? std::string(scan_type) : "Scan rapide",
        timing_flag,
        ports ? std::string(ports) : ""
    };
    if (scan_type) g_free(scan_type);

    // Reset UI
    gtk_list_store_clear(app.host_store);
    gtk_list_store_clear(app.port_store);
    gtk_text_buffer_set_text(app.raw_buffer, "", -1);
    gtk_label_set_text(GTK_LABEL(app.summary_label), "Scan en cours...");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), 0.0);
    gtk_label_set_text(GTK_LABEL(app.host_count_label), "…");
    gtk_label_set_text(GTK_LABEL(app.port_count_label), "…");

    gtk_widget_set_sensitive(app.scan_btn, FALSE);
    gtk_widget_set_sensitive(app.stop_btn, TRUE);
    gtk_spinner_start(GTK_SPINNER(app.spinner));

    scan_running = true;

    // Progress animation
    g_timeout_add(400, on_progress_update, nullptr);

    // Launch in thread
    std::thread t(scan_thread, params);
    t.detach();
}

static void on_stop_clicked(GtkWidget*, gpointer) {
    if (!scan_running) return;
    system("pkill -f 'nmap ' 2>/dev/null");
    scan_running = false;
    gtk_widget_set_sensitive(app.scan_btn, TRUE);
    gtk_widget_set_sensitive(app.stop_btn, FALSE);
    gtk_spinner_stop(GTK_SPINNER(app.spinner));
    gtk_label_set_text(GTK_LABEL(app.status_label), "Scan interrompu.");
}

// ─── Export CSV ───────────────────────────────────────────────────────────────

static void on_export_clicked(GtkWidget*, gpointer) {
    GtkWidget* dlg = gtk_file_chooser_dialog_new(
        "Exporter en CSV",
        GTK_WINDOW(app.window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Annuler", GTK_RESPONSE_CANCEL,
        "_Enregistrer", GTK_RESPONSE_ACCEPT,
        nullptr);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "scan_result.csv");

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        gchar* fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        FILE* f = fopen(fname, "w");
        if (f) {
            fprintf(f, "IP,Hostname,Status,OS,MAC,Vendor,Latence,Port,Protocol,State,Service,Version\n");
            std::lock_guard<std::mutex> lock(result_mutex);
            for (auto& h : scan_results) {
                if (h.ports.empty()) {
                    fprintf(f, "%s,%s,%s,%s,%s,%s,%s,,,,\n",
                        h.ip.c_str(), h.hostname.c_str(), h.status.c_str(),
                        h.os_guess.c_str(), h.mac.c_str(), h.vendor.c_str(),
                        h.latency.c_str());
                } else {
                    for (auto& p : h.ports) {
                        fprintf(f, "%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s\n",
                            h.ip.c_str(), h.hostname.c_str(), h.status.c_str(),
                            h.os_guess.c_str(), h.mac.c_str(), h.vendor.c_str(),
                            h.latency.c_str(), p.port, p.protocol.c_str(),
                            p.state.c_str(), p.service.c_str(), p.version.c_str());
                    }
                }
            }
            fclose(f);
        }
        g_free(fname);
    }
    gtk_widget_destroy(dlg);
}

// ─── UI Builder ───────────────────────────────────────────────────────────────

static GtkWidget* build_control_panel() {
    GtkWidget* panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(panel), "panel");
    gtk_widget_set_margin_start(panel, 10);
    gtk_widget_set_margin_end(panel, 10);
    gtk_widget_set_margin_top(panel, 10);
    gtk_widget_set_margin_bottom(panel, 0);

    // Title
    GtkWidget* title = gtk_label_new("⬡  PARAMÈTRES DE SCAN");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "panel-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(panel), title, FALSE, FALSE, 0);

    // Target
    GtkWidget* target_lbl = gtk_label_new("Cible  (IP · CIDR · hostname)");
    gtk_style_context_add_class(gtk_widget_get_style_context(target_lbl), "info-label");
    gtk_widget_set_halign(target_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(panel), target_lbl, FALSE, FALSE, 0);

    app.target_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.target_entry),
        "ex: 192.168.1.0/24  ou  scanme.nmap.org");
    gtk_box_pack_start(GTK_BOX(panel), app.target_entry, FALSE, FALSE, 0);

    // Scan type
    GtkWidget* type_lbl = gtk_label_new("Type de scan");
    gtk_style_context_add_class(gtk_widget_get_style_context(type_lbl), "info-label");
    gtk_widget_set_halign(type_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(panel), type_lbl, FALSE, FALSE, 0);

    app.scan_type_combo = gtk_combo_box_text_new();
    const char* scan_types[] = {
        "Scan rapide", "Ping Sweep", "TCP Connect",
        "SYN Scan", "UDP Scan", "Service Version",
        "OS Detection", "Agressif (-A)", nullptr
    };
    for (int i = 0; scan_types[i]; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.scan_type_combo), scan_types[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(app.scan_type_combo), 0);
    gtk_box_pack_start(GTK_BOX(panel), app.scan_type_combo, FALSE, FALSE, 0);

    // Timing
    GtkWidget* timing_lbl = gtk_label_new("Timing");
    gtk_style_context_add_class(gtk_widget_get_style_context(timing_lbl), "info-label");
    gtk_widget_set_halign(timing_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(panel), timing_lbl, FALSE, FALSE, 0);

    app.timing_combo = gtk_combo_box_text_new();
    const char* timings[] = {
        "T0 — Paranoïaque", "T1 — Furtif", "T2 — Poli",
        "T3 — Normal", "T4 — Agressif", "T5 — Insane", nullptr
    };
    for (int i = 0; timings[i]; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.timing_combo), timings[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(app.timing_combo), 3);
    gtk_box_pack_start(GTK_BOX(panel), app.timing_combo, FALSE, FALSE, 0);

    // Ports
    GtkWidget* ports_lbl = gtk_label_new("Ports  (vide = défaut)");
    gtk_style_context_add_class(gtk_widget_get_style_context(ports_lbl), "info-label");
    gtk_widget_set_halign(ports_lbl, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(panel), ports_lbl, FALSE, FALSE, 0);

    app.ports_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.ports_entry),
        "ex: 22,80,443  ou  1-1024  ou  -");
    gtk_box_pack_start(GTK_BOX(panel), app.ports_entry, FALSE, FALSE, 0);

    // Buttons
    GtkWidget* btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(btn_box, 4);
    gtk_box_pack_start(GTK_BOX(panel), btn_box, FALSE, FALSE, 0);

    app.scan_btn = gtk_button_new_with_label("▶  SCANNER");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.scan_btn), "btn-scan");
    gtk_widget_set_hexpand(app.scan_btn, TRUE);
    g_signal_connect(app.scan_btn, "clicked", G_CALLBACK(on_scan_clicked), nullptr);
    gtk_box_pack_start(GTK_BOX(btn_box), app.scan_btn, TRUE, TRUE, 0);

    app.stop_btn = gtk_button_new_with_label("■  STOP");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.stop_btn), "btn-stop");
    gtk_widget_set_sensitive(app.stop_btn, FALSE);
    g_signal_connect(app.stop_btn, "clicked", G_CALLBACK(on_stop_clicked), nullptr);
    gtk_box_pack_start(GTK_BOX(btn_box), app.stop_btn, FALSE, FALSE, 0);

    // Export
    GtkWidget* export_btn = gtk_button_new_with_label("⬇  Exporter CSV");
    gtk_box_pack_start(GTK_BOX(panel), export_btn, FALSE, FALSE, 0);
    g_signal_connect(export_btn, "clicked", G_CALLBACK(on_export_clicked), nullptr);

    // Progress
    gtk_box_pack_start(GTK_BOX(panel), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 4);

    app.progress_bar = gtk_progress_bar_new();
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), 0.0);
    gtk_box_pack_start(GTK_BOX(panel), app.progress_bar, FALSE, FALSE, 0);

    // Stats row
    GtkWidget* stats_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(stats_box, 4);

    GtkWidget* h_lbl = gtk_label_new("Hôtes :");
    gtk_style_context_add_class(gtk_widget_get_style_context(h_lbl), "info-label");
    gtk_box_pack_start(GTK_BOX(stats_box), h_lbl, FALSE, FALSE, 0);

    app.host_count_label = gtk_label_new("0");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.host_count_label), "counter-badge");
    gtk_box_pack_start(GTK_BOX(stats_box), app.host_count_label, FALSE, FALSE, 0);

    GtkWidget* p_lbl = gtk_label_new("Ports :");
    gtk_style_context_add_class(gtk_widget_get_style_context(p_lbl), "info-label");
    gtk_box_pack_start(GTK_BOX(stats_box), p_lbl, FALSE, FALSE, 0);

    app.port_count_label = gtk_label_new("0");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.port_count_label), "counter-badge");
    gtk_box_pack_start(GTK_BOX(stats_box), app.port_count_label, FALSE, FALSE, 0);

    app.spinner = gtk_spinner_new();
    gtk_box_pack_end(GTK_BOX(stats_box), app.spinner, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(panel), stats_box, FALSE, FALSE, 0);

    return panel;
}

static GtkWidget* build_host_tree() {
    // Columns: IP, Hostname, Status, OS, MAC, Vendor, Latency, #Ports
    app.host_store = gtk_list_store_new(8,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_INT);

    app.host_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app.host_store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(app.host_tree), TRUE);

    struct ColDef { const char* title; int idx; };
    ColDef cols[] = {
        {"IP", 0}, {"Hostname", 1}, {"Statut", 2},
        {"OS", 3}, {"MAC", 4}, {"Fabricant", 5},
        {"Latence", 6}, {"Ports", 7}
    };

    for (auto& c : cols) {
        GtkCellRenderer* r;
        GtkTreeViewColumn* col;
        if (c.idx == 7) {
            r = gtk_cell_renderer_text_new();
            col = gtk_tree_view_column_new_with_attributes(c.title, r, "text", c.idx, nullptr);
        } else {
            r = gtk_cell_renderer_text_new();
            col = gtk_tree_view_column_new_with_attributes(c.title, r, "text", c.idx, nullptr);
        }
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, 80);
        gtk_tree_view_append_column(GTK_TREE_VIEW(app.host_tree), col);
    }

    GtkTreeSelection* sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app.host_tree));
    g_signal_connect(sel, "changed", G_CALLBACK(on_host_selected), nullptr);

    GtkWidget* sw = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), app.host_tree);
    return sw;
}

static GtkWidget* build_port_tree() {
    app.port_store = gtk_list_store_new(5,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING);

    app.port_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app.port_store));

    struct ColDef { const char* title; int idx; };
    ColDef cols[] = {
        {"Port", 0}, {"Proto", 1}, {"État", 2},
        {"Service", 3}, {"Version / Banner", 4}
    };
    for (auto& c : cols) {
        GtkCellRenderer* r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn* col = gtk_tree_view_column_new_with_attributes(
            c.title, r, "text", c.idx, nullptr);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, 70);
        gtk_tree_view_append_column(GTK_TREE_VIEW(app.port_tree), col);
    }

    GtkWidget* sw = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), app.port_tree);
    return sw;
}

static GtkWidget* build_raw_view() {
    app.raw_buffer = gtk_text_buffer_new(nullptr);
    app.raw_output = gtk_text_view_new_with_buffer(app.raw_buffer);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app.raw_output), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app.raw_output), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app.raw_output), "raw-output");

    GtkWidget* sw = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), app.raw_output);
    return sw;
}

// ─── Main window ──────────────────────────────────────────────────────────────

static GtkWidget* build_main_window() {
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app.window), "NmapGUI — Network Scanner");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 1280, 820);
    gtk_window_set_position(GTK_WINDOW(app.window), GTK_WIN_POS_CENTER);
    g_signal_connect(app.window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), root);

    // ── Header ──
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(header), "header-bar");
    gtk_widget_set_margin_start(header, 16);
    gtk_widget_set_margin_end(header, 16);
    gtk_widget_set_margin_top(header, 10);
    gtk_widget_set_margin_bottom(header, 10);
    gtk_box_pack_start(GTK_BOX(root), header, FALSE, FALSE, 0);

    GtkWidget* logo = gtk_label_new("⬡ NMAPGUI");
    gtk_style_context_add_class(gtk_widget_get_style_context(logo), "title-label");
    gtk_box_pack_start(GTK_BOX(header), logo, FALSE, FALSE, 0);

    GtkWidget* sub = gtk_label_new("Network Discovery & Security Auditing");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "subtitle-label");
    gtk_box_pack_start(GTK_BOX(header), sub, FALSE, FALSE, 8);

    // ── Body (horizontal) ──
    GtkWidget* body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(root), body, TRUE, TRUE, 0);

    // Left: control panel
    GtkWidget* left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(left, 300, -1);
    gtk_box_pack_start(GTK_BOX(body), left, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left), build_control_panel(), FALSE, FALSE, 0);

    // Separator
    GtkWidget* vsep = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_margin_top(vsep, 10);
    gtk_widget_set_margin_bottom(vsep, 10);
    gtk_box_pack_start(GTK_BOX(body), vsep, FALSE, FALSE, 6);

    // Right: results notebook
    GtkWidget* right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(body), right, TRUE, TRUE, 0);

    // Summary
    app.summary_label = gtk_label_new("Lancez un scan pour découvrir les hôtes du réseau.");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.summary_label), "info-label");
    gtk_widget_set_halign(app.summary_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(app.summary_label, 10);
    gtk_widget_set_margin_top(app.summary_label, 10);
    gtk_widget_set_margin_bottom(app.summary_label, 6);
    gtk_box_pack_start(GTK_BOX(right), app.summary_label, FALSE, FALSE, 0);

    // Notebook
    GtkWidget* nb = gtk_notebook_new();
    gtk_widget_set_margin_start(nb, 10);
    gtk_widget_set_margin_end(nb, 10);
    gtk_widget_set_margin_bottom(nb, 0);
    gtk_box_pack_start(GTK_BOX(right), nb, TRUE, TRUE, 0);

    // Tab 1: Hosts
    GtkWidget* hosts_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_top(hosts_box, 8);
    gtk_box_pack_start(GTK_BOX(hosts_box), build_host_tree(), TRUE, TRUE, 0);
    GtkWidget* sel_lbl = gtk_label_new("▾  Ports de l'hôte sélectionné");
    gtk_style_context_add_class(gtk_widget_get_style_context(sel_lbl), "panel-title");
    gtk_widget_set_halign(sel_lbl, GTK_ALIGN_START);
    gtk_widget_set_margin_top(sel_lbl, 6);
    gtk_box_pack_start(GTK_BOX(hosts_box), sel_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hosts_box), build_port_tree(), TRUE, TRUE, 0);

    gtk_notebook_append_page(GTK_NOTEBOOK(nb), hosts_box,
        gtk_label_new("⬡  Hôtes & Ports"));

    // Tab 2: Raw output
    GtkWidget* raw_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(raw_box, 8);
    gtk_box_pack_start(GTK_BOX(raw_box), build_raw_view(), TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), raw_box,
        gtk_label_new("⬡  Sortie brute"));

    // Status bar
    GtkWidget* statusbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(statusbar), "status-bar");
    gtk_box_pack_start(GTK_BOX(root), statusbar, FALSE, FALSE, 0);

    app.status_label = gtk_label_new("Prêt  ·  nmap disponible");
    gtk_widget_set_halign(app.status_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(statusbar), app.status_label, TRUE, TRUE, 0);

    GtkWidget* ver = gtk_label_new("NmapGUI v1.0  ·  C++ / GTK3");
    gtk_widget_set_halign(ver, GTK_ALIGN_END);
    gtk_box_pack_end(GTK_BOX(statusbar), ver, FALSE, FALSE, 0);

    return app.window;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    gtk_init(&argc, &argv);

    // Apply CSS theme
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS_THEME, -1, nullptr);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget* win = build_main_window();
    gtk_widget_show_all(win);
    gtk_widget_set_sensitive(app.stop_btn, FALSE);

    gtk_main();
    return 0;
}
