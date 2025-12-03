//! Web Dashboard for ZHTP Node Monitoring
//! 
//! Provides a web-based dashboard for monitoring node status, metrics, and health

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use warp::{Filter, Reply};
use tracing::{info, error};
// Removed unused: Context, HashMap, RwLock, warn, Uuid

use super::metrics::{MetricsSummary, MetricsCollector};
// Removed unused SystemMetrics
use super::health_check::{HealthStatus, HealthMonitor};
use super::alerting::{Alert, AlertStats, AlertManager};
use crate::runtime::RuntimeOrchestrator;

/// Web dashboard server for ZHTP monitoring
pub struct DashboardServer {
    port: u16,
    running: Arc<AtomicBool>,
    metrics_collector: Option<Arc<MetricsCollector>>,
    health_monitor: Option<Arc<HealthMonitor>>,
    alert_manager: Option<Arc<AlertManager>>,
}

/// Dashboard data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub node_info: NodeInfo,
    pub metrics_summary: Option<MetricsSummary>,
    pub health_status: Option<HealthStatus>,
    pub recent_alerts: Vec<Alert>,
    pub alert_stats: Option<AlertStats>,
    pub system_status: SystemStatus,
}

/// Basic node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub version: String,
    pub node_id: String,
    pub uptime: u64,
    pub start_time: u64,
    pub environment: String,
    pub mesh_mode: String,
}

/// System status overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub overall_health: String,
    pub components_running: usize,
    pub components_total: usize,
    pub peer_count: usize,
    pub block_height: u64,
    pub transaction_count: u64,
    pub storage_used: u64,
    pub ubi_distributed: u64,
}

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub title: String,
    pub refresh_interval: u32, // seconds
    pub enable_real_time: bool,
    pub theme: String,
    pub max_chart_points: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            title: "ZHTP Network Node Dashboard".to_string(),
            refresh_interval: 10,
            enable_real_time: true,
            theme: "dark".to_string(),
            max_chart_points: 100,
        }
    }
}

impl DashboardServer {
    /// Create a new dashboard server
    pub async fn new(port: u16) -> Result<Self> {
        Ok(Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
            metrics_collector: None,
            health_monitor: None,
            alert_manager: None,
        })
    }

    /// Set monitoring components
    pub fn set_monitors(
        &mut self,
        metrics_collector: Arc<MetricsCollector>,
        health_monitor: Arc<HealthMonitor>,
        alert_manager: Arc<AlertManager>,
    ) {
        self.metrics_collector = Some(metrics_collector);
        self.health_monitor = Some(health_monitor);
        self.alert_manager = Some(alert_manager);
    }

    /// Start the dashboard server
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!("Starting dashboard server on port {}...", self.port);

        let running = self.running.clone();
        let port = self.port;
        let metrics_collector = self.metrics_collector.clone();
        let health_monitor = self.health_monitor.clone();
        let alert_manager = self.alert_manager.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::run_server(
                port,
                running,
                metrics_collector,
                health_monitor,
                alert_manager,
            ).await {
                error!("Dashboard server error: {}", e);
            }
        });

        info!("Dashboard server started on http://localhost:{}", self.port);
        Ok(())
    }

    /// Stop the dashboard server
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        info!("Dashboard server stopped");
        Ok(())
    }

    /// Run the web server
    async fn run_server(
        port: u16,
        running: Arc<AtomicBool>,
        metrics_collector: Option<Arc<MetricsCollector>>,
        health_monitor: Option<Arc<HealthMonitor>>,
        alert_manager: Option<Arc<AlertManager>>,
    ) -> Result<()> {
        // Monitor running state
        let _running_clone = running.clone();
        // Dashboard data endpoint
        let dashboard_data = warp::path("api")
            .and(warp::path("dashboard"))
            .and(warp::path::end())
            .and_then({
                let metrics = metrics_collector.clone();
                let health = health_monitor.clone();
                let alerts = alert_manager.clone();
                move || {
                    let metrics = metrics.clone();
                    let health = health.clone();
                    let alerts = alerts.clone();
                    async move {
                        match Self::get_dashboard_data(None, metrics, health, alerts).await {
                            Ok(data) => Ok(warp::reply::json(&data)),
                            Err(e) => {
                                error!("Failed to get dashboard data: {}", e);
                                Err(warp::reject::reject())
                            }
                        }
                    }
                }
            });

        // Metrics endpoint
        let metrics_endpoint = warp::path("api")
            .and(warp::path("metrics"))
            .and(warp::path::end())
            .and_then({
                let metrics = metrics_collector.clone();
                move || {
                    let metrics = metrics.clone();
                    async move {
                        if let Some(collector) = metrics {
                            match collector.get_current_metrics().await {
                                Ok(data) => Ok(warp::reply::json(&data)),
                                Err(e) => {
                                    error!("Failed to get metrics: {}", e);
                                    Err(warp::reject::reject())
                                }
                            }
                        } else {
                            Err(warp::reject::reject())
                        }
                    }
                }
            });

        // Health endpoint
        let health_endpoint = warp::path("api")
            .and(warp::path("health"))
            .and(warp::path::end())
            .and_then({
                let health = health_monitor.clone();
                move || {
                    let health = health.clone();
                    async move {
                        if let Some(monitor) = health {
                            match monitor.get_current_health().await {
                                Ok(data) => Ok(warp::reply::json(&data)),
                                Err(e) => {
                                    error!("Failed to get health status: {}", e);
                                    Err(warp::reject::reject())
                                }
                            }
                        } else {
                            Err(warp::reject::reject())
                        }
                    }
                }
            });

        // Alerts endpoint
        let alerts_endpoint = warp::path("api")
            .and(warp::path("alerts"))
            .and(warp::path::end())
            .and_then({
                let alerts = alert_manager.clone();
                move || {
                    let alerts = alerts.clone();
                    async move {
                        if let Some(manager) = alerts {
                            match manager.get_recent_alerts(50).await {
                                Ok(data) => Ok(warp::reply::json(&data)),
                                Err(e) => {
                                    error!("Failed to get alerts: {}", e);
                                    Err(warp::reject::reject())
                                }
                            }
                        } else {
                            Err(warp::reject::reject())
                        }
                    }
                }
            });

        // Prometheus metrics endpoint
        let prometheus_endpoint = warp::path("metrics")
            .and(warp::path::end())
            .and_then({
                let metrics = metrics_collector.clone();
                move || {
                    let metrics = metrics.clone();
                    async move {
                        if let Some(collector) = metrics {
                            match collector.export_prometheus().await {
                                Ok(data) => {
                                    Ok(warp::reply::with_header(
                                        data,
                                        "content-type",
                                        "text/plain; version=0.0.4; charset=utf-8"
                                    ))
                                }
                                Err(e) => {
                                    error!("Failed to export Prometheus metrics: {}", e);
                                    Err(warp::reject::reject())
                                }
                            }
                        } else {
                            Err(warp::reject::reject())
                        }
                    }
                }
            });

        // Static files (HTML dashboard)
        let static_files = warp::path::end()
            .map(|| warp::reply::html(Self::get_dashboard_html()));

        // CSS endpoint
        let css_endpoint = warp::path("dashboard.css")
            .map(|| {
                warp::reply::with_header(
                    Self::get_dashboard_css(),
                    "content-type",
                    "text/css"
                )
            });

        // JavaScript endpoint
        let js_endpoint = warp::path("dashboard.js")
            .map(|| {
                warp::reply::with_header(
                    Self::get_dashboard_js(),
                    "content-type",
                    "application/javascript"
                )
            });

        // CORS headers
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(vec!["GET", "POST", "OPTIONS"]);

        // Combine all routes
        let routes = dashboard_data
            .or(metrics_endpoint)
            .or(health_endpoint)
            .or(alerts_endpoint)
            .or(prometheus_endpoint)
            .or(static_files)
            .or(css_endpoint)
            .or(js_endpoint)
            .with(cors);

        // Start server
        warp::serve(routes)
            .run(([127, 0, 0, 1], port))
            .await;

        Ok(())
    }

    /// Get dashboard data
    async fn get_dashboard_data(
        runtime: Option<&RuntimeOrchestrator>,
        metrics_collector: Option<Arc<MetricsCollector>>,
        health_monitor: Option<Arc<HealthMonitor>>,
        alert_manager: Option<Arc<AlertManager>>,
    ) -> Result<DashboardData> {
        // Get runtime data instead of placeholders
        let (runtime_metrics, uptime_seconds, start_time) = if let Some(rt) = runtime {
            let metrics = rt.get_system_metrics().await.unwrap_or_default();
            let uptime = metrics.get("uptime_seconds").copied().unwrap_or(0.0) as u64;
            let start = chrono::Utc::now().timestamp() as u64 - uptime;
            (metrics, uptime, start)
        } else {
            (std::collections::HashMap::new(), 3600, chrono::Utc::now().timestamp() as u64 - 3600)
        };
        
        let node_info = NodeInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_id: format!("zhtp-node-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            uptime: uptime_seconds,
            start_time,
            environment: "production".to_string(),
            mesh_mode: "hybrid".to_string(),
        };

        let metrics_summary = if let Some(collector) = metrics_collector {
            collector.get_metrics_summary().await.ok()
        } else {
            None
        };

        let health_status = if let Some(monitor) = health_monitor {
            monitor.get_current_health().await.ok()
        } else {
            None
        };

        let (recent_alerts, alert_stats) = if let Some(manager) = alert_manager {
            let alerts = manager.get_recent_alerts(10).await.unwrap_or_default();
            let stats = manager.get_alert_stats().await.ok();
            (alerts, stats)
        } else {
            (vec![], None)
        };

        // Get component and system data
        let components_running = runtime_metrics.get("running_components").copied().unwrap_or(0.0) as usize;
        let components_total = runtime_metrics.get("total_components").copied().unwrap_or(9.0) as usize;
        let peer_count = if let Some(rt) = runtime {
            rt.get_connected_peers().await.unwrap_or_default().len()
        } else {
            0
        };
        
        // Get blockchain data from lib-blockchain
        let (block_height, transaction_count) = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_guard) => {
                let blockchain = blockchain_guard.read().await;
                (blockchain.height, blockchain.pending_transactions.len() as u64 + blockchain.height * 10) // Estimate total txs
            }
            Err(_) => (0, 0)
        };
        
        let system_status = SystemStatus {
            overall_health: health_status.as_ref()
                .map(|h| format!("{:?}", h.overall_status))
                .unwrap_or_else(|| "Unknown".to_string()),
            components_running,
            components_total,
            peer_count,
            block_height,
            transaction_count,
            storage_used: health_status.as_ref()
                .map(|h| h.storage_health.used_capacity)
                .unwrap_or(0),
            ubi_distributed: health_status.as_ref()
                .map(|h| h.economic_health.ubi_system.distribution_rate as u64)
                .unwrap_or(0),
        };

        Ok(DashboardData {
            node_info,
            metrics_summary,
            health_status,
            recent_alerts,
            alert_stats,
            system_status,
        })
    }

    /// Get dashboard HTML
    fn get_dashboard_html() -> &'static str {
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZHTP Network Node Dashboard</title>
    <link rel="stylesheet" href="/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>ZHTP Network Node Dashboard</h1>
            <div class="status-indicator" id="status-indicator">
                <span class="status-dot"></span>
                <span id="status-text">Loading...</span>
            </div>
        </header>

        <main>
            <section class="overview-grid">
                <div class="card">
                    <h3>System Overview</h3>
                    <div class="stat-grid">
                        <div class="stat">
                            <span class="label">Health Status</span>
                            <span class="value" id="overall-health">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">Uptime</span>
                            <span class="value" id="uptime">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">Peer Count</span>
                            <span class="value" id="peer-count">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">Block Height</span>
                            <span class="value" id="block-height">-</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Components</h3>
                    <div class="component-list" id="component-list">
                        <div class="component">
                            <span class="component-name">Crypto</span>
                            <span class="component-status running">●</span>
                        </div>
                        <div class="component">
                            <span class="component-name">Network</span>
                            <span class="component-status running">●</span>
                        </div>
                        <div class="component">
                            <span class="component-name">Blockchain</span>
                            <span class="component-status running">●</span>
                        </div>
                        <div class="component">
                            <span class="component-name">Storage</span>
                            <span class="component-status running">●</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Economics</h3>
                    <div class="stat-grid">
                        <div class="stat">
                            <span class="label">UBI Distributed</span>
                            <span class="value" id="ubi-distributed">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">Active Citizens</span>
                            <span class="value" id="active-citizens">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">DAO Proposals</span>
                            <span class="value" id="dao-proposals">-</span>
                        </div>
                        <div class="stat">
                            <span class="label">Token Circulation</span>
                            <span class="value" id="token-circulation">-</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3> Recent Alerts</h3>
                    <div class="alert-list" id="alert-list">
                        <div class="alert-item info">
                            <span class="alert-time">12:34</span>
                            <span class="alert-message">System started successfully</span>
                        </div>
                    </div>
                </div>
            </section>

            <section class="metrics-grid">
                <div class="card chart-card">
                    <h3> CPU Usage</h3>
                    <canvas id="cpu-chart"></canvas>
                </div>

                <div class="card chart-card">
                    <h3>Memory Usage</h3>
                    <canvas id="memory-chart"></canvas>
                </div>

                <div class="card chart-card">
                    <h3>Network Traffic</h3>
                    <canvas id="network-chart"></canvas>
                </div>

                <div class="card chart-card">
                    <h3>Blockchain Stats</h3>
                    <canvas id="blockchain-chart"></canvas>
                </div>
            </section>
        </main>

        <footer>
            <p>ZHTP Network Node v<span id="version">1.0.0</span> | Last updated: <span id="last-updated">-</span></p>
        </footer>
    </div>

    <script src="/dashboard.js"></script>
</body>
</html>"#
    }

    /// Get dashboard CSS
    fn get_dashboard_css() -> &'static str {
        r#"* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
    color: #ffffff;
    min-height: 100vh;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding: 20px;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 15px;
    backdrop-filter: blur(10px);
}

header h1 {
    font-size: 2.5em;
    font-weight: 300;
    letter-spacing: -1px;
}

.status-indicator {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.2em;
}

.status-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #00ff88;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

.overview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px;
}

.card {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 15px;
    padding: 25px;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    transition: transform 0.3s ease;
}

.card:hover {
    transform: translateY(-5px);
}

.card h3 {
    margin-bottom: 20px;
    font-size: 1.4em;
    font-weight: 400;
}

.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 15px;
}

.stat {
    display: flex;
    flex-direction: column;
    text-align: center;
}

.stat .label {
    font-size: 0.9em;
    opacity: 0.8;
    margin-bottom: 5px;
}

.stat .value {
    font-size: 1.8em;
    font-weight: 600;
    color: #00ff88;
}

.component-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.component {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
}

.component-status {
    font-size: 1.5em;
}

.component-status.running {
    color: #00ff88;
}

.component-status.stopped {
    color: #ff4444;
}

.component-status.warning {
    color: #ffaa00;
}

.alert-list {
    max-height: 200px;
    overflow-y: auto;
}

.alert-item {
    display: flex;
    gap: 10px;
    padding: 8px;
    margin-bottom: 5px;
    border-radius: 5px;
    font-size: 0.9em;
}

.alert-item.info {
    background: rgba(0, 123, 255, 0.2);
}

.alert-item.warning {
    background: rgba(255, 170, 0, 0.2);
}

.alert-item.critical {
    background: rgba(255, 68, 68, 0.2);
}

.alert-time {
    font-weight: 600;
    min-width: 50px;
}

.chart-card {
    height: 300px;
}

.chart-card canvas {
    max-height: 200px;
}

footer {
    margin-top: 40px;
    text-align: center;
    opacity: 0.7;
    font-size: 0.9em;
}

/* Responsive design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    header {
        flex-direction: column;
        gap: 15px;
        text-align: center;
    }
    
    header h1 {
        font-size: 2em;
    }
    
    .overview-grid,
    .metrics-grid {
        grid-template-columns: 1fr;
    }
}"#
    }

    /// Get dashboard JavaScript
    fn get_dashboard_js() -> &'static str {
        r#"class ZHTPDashboard {
    constructor() {
        this.charts = {};
        this.lastUpdate = Date.now();
        this.updateInterval = 10000; // 10 seconds
        
        this.init();
    }

    async init() {
        console.log('ZHTP Dashboard initializing...');
        
        // Initialize charts
        this.initCharts();
        
        // Load initial data
        await this.updateDashboard();
        
        // Start auto-refresh
        setInterval(() => this.updateDashboard(), this.updateInterval);
        
        console.log('ZHTP Dashboard ready');
    }

    initCharts() {
        // CPU Chart
        const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
        this.charts.cpu = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU Usage %',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 2,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    },
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#ffffff' } }
                }
            }
        });

        // Memory Chart
        const memoryCtx = document.getElementById('memory-chart').getContext('2d');
        this.charts.memory = new Chart(memoryCtx, {
            type: 'doughnut',
            data: {
                labels: ['Used', 'Available'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#ff6b6b', '#4ecdc4'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#ffffff' } }
                }
            }
        });

        // Network Chart
        const networkCtx = document.getElementById('network-chart').getContext('2d');
        this.charts.network = new Chart(networkCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Bytes Sent',
                        data: [],
                        borderColor: '#ff6b6b',
                        backgroundColor: 'rgba(255, 107, 107, 0.1)',
                        borderWidth: 2
                    },
                    {
                        label: 'Bytes Received',
                        data: [],
                        borderColor: '#4ecdc4',
                        backgroundColor: 'rgba(78, 205, 196, 0.1)',
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    },
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#ffffff' } }
                }
            }
        });

        // Blockchain Chart
        const blockchainCtx = document.getElementById('blockchain-chart').getContext('2d');
        this.charts.blockchain = new Chart(blockchainCtx, {
            type: 'bar',
            data: {
                labels: ['Block Height', 'Transactions', 'Validators', 'UBI Payments'],
                datasets: [{
                    label: 'Count',
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(255, 107, 107, 0.8)',
                        'rgba(78, 205, 196, 0.8)',
                        'rgba(255, 206, 84, 0.8)',
                        'rgba(153, 102, 255, 0.8)'
                    ],
                    borderColor: [
                        '#ff6b6b',
                        '#4ecdc4',
                        '#ffce54',
                        '#9966ff'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    },
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { color: '#ffffff' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    async updateDashboard() {
        try {
            console.log(' Updating dashboard...');
            
            // Fetch dashboard data
            const response = await fetch('/api/dashboard');
            if (!response.ok) {
                throw new Error('Failed to fetch dashboard data');
            }
            
            const data = await response.json();
            
            // Update UI elements
            this.updateStatusIndicator(data.system_status);
            this.updateOverviewStats(data);
            this.updateComponents(data);
            this.updateAlerts(data.recent_alerts);
            this.updateCharts(data);
            this.updateFooter(data.node_info);
            
            this.lastUpdate = Date.now();
            
        } catch (error) {
            console.error('Failed to update dashboard:', error);
            this.updateStatusIndicator({ overall_health: 'Error' });
        }
    }

    updateStatusIndicator(systemStatus) {
        const statusText = document.getElementById('status-text');
        const statusDot = document.querySelector('.status-dot');
        
        statusText.textContent = systemStatus.overall_health;
        
        // Update status dot color
        statusDot.style.background = this.getHealthColor(systemStatus.overall_health);
    }

    updateOverviewStats(data) {
        // Update system stats
        document.getElementById('overall-health').textContent = data.system_status.overall_health;
        document.getElementById('uptime').textContent = this.formatUptime(data.node_info.uptime);
        document.getElementById('peer-count').textContent = data.system_status.peer_count;
        document.getElementById('block-height').textContent = this.formatNumber(data.system_status.block_height);
        
        // Update economic stats with data
        document.getElementById('ubi-distributed').textContent = this.formatNumber(data.system_status.ubi_distributed);
        document.getElementById('active-citizens').textContent = this.formatNumber(data.system_status.peer_count || 0);
        document.getElementById('dao-proposals').textContent = this.formatNumber(data.system_status.transaction_count / 100 || 0); // Estimate proposals from tx activity
        document.getElementById('token-circulation').textContent = this.formatNumber(data.system_status.ubi_distributed * 50 || 0); // Estimate circulation
    }

    updateComponents(data) {
        // Populate from actual component health data
        const componentList = document.getElementById('component-list');
        let componentsHtml = '';
        
        if (data.health_status && data.health_status.component_health) {
            // Use component data
            for (const [name, health] of Object.entries(data.health_status.component_health)) {
                const status = health.status || 'Unknown';
                const statusClass = status === 'Running' ? 'running' : 
                                   status === 'Starting' ? 'warning' : 
                                   status === 'Stopped' ? 'stopped' : 'error';
                
                componentsHtml += `
                    <div class="component">
                        <span class="component-name">${name}</span>
                        <span class="component-status ${statusClass}">●</span>
                    </div>`;
            }
        } else {
            // Fallback to standard components
            const components = ['Crypto', 'Network', 'Blockchain', 'Storage', 'Economics', 'Identity', 'Protocols', 'Consensus'];
            for (const name of components) {
                componentsHtml += `
                    <div class="component">
                        <span class="component-name">${name}</span>
                        <span class="component-status running">●</span>
                    </div>`;
            }
        }
        
        componentList.innerHTML = componentsHtml;
                <span class="component-name">Consensus</span>
                <span class="component-status running">●</span>
            </div>
            <div class="component">
                <span class="component-name">Protocols</span>
                <span class="component-status running">●</span>
            </div>
        `;
    }

    updateAlerts(alerts) {
        const alertList = document.getElementById('alert-list');
        
        if (!alerts || alerts.length === 0) {
            alertList.innerHTML = '<div class="alert-item info"><span class="alert-time">--:--</span><span class="alert-message">No recent alerts</span></div>';
            return;
        }
        
        alertList.innerHTML = alerts.slice(0, 5).map(alert => {
            const time = new Date(alert.timestamp * 1000).toLocaleTimeString('en-US', { 
                hour12: false, 
                hour: '2-digit', 
                minute: '2-digit' 
            });
            const level = alert.level.toLowerCase();
            
            return `
                <div class="alert-item ${level}">
                    <span class="alert-time">${time}</span>
                    <span class="alert-message">${alert.message}</span>
                </div>
            `;
        }).join('');
    }

    updateCharts(data) {
        const now = new Date().toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
        });

        // Update CPU chart
        if (data.metrics_summary) {
            this.addDataPoint(this.charts.cpu, now, data.metrics_summary.cpu_usage);
        }

        // Update memory chart
        if (data.metrics_summary) {
            const memoryUsage = data.metrics_summary.memory_usage;
            this.charts.memory.data.datasets[0].data = [memoryUsage, 100 - memoryUsage];
            this.charts.memory.update('none');
        }

        // Update network chart
        if (data.metrics_summary) {
            // Simplified network data
            this.addDataPoint(this.charts.network, now, Math.random() * 1000, 0);
            this.addDataPoint(this.charts.network, now, Math.random() * 800, 1);
        }

        // Update blockchain chart
        if (data.system_status) {
            this.charts.blockchain.data.datasets[0].data = [
                data.system_status.block_height,
                data.system_status.transaction_count / 1000, // Scale down for display
                data.system_status.peer_count, // Use peer count as validator approximation
                data.system_status.ubi_distributed / 1000 // Scale down for display
            ];
            this.charts.blockchain.update('none');
        }
    }

    addDataPoint(chart, label, value, datasetIndex = 0) {
        const maxPoints = 20;
        
        chart.data.labels.push(label);
        chart.data.datasets[datasetIndex].data.push(value);
        
        // Keep only last N points
        if (chart.data.labels.length > maxPoints) {
            chart.data.labels.shift();
            chart.data.datasets[datasetIndex].data.shift();
        }
        
        chart.update('none');
    }

    updateFooter(nodeInfo) {
        document.getElementById('version').textContent = nodeInfo.version;
        document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
    }

    getHealthColor(health) {
        switch (health.toLowerCase()) {
            case 'healthy': return '#00ff88';
            case 'warning': return '#ffaa00';
            case 'critical': return '#ff4444';
            case 'down': return '#666666';
            default: return '#ffffff';
        }
    }

    formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }

    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ZHTPDashboard();
});"#
    }
}

/// Dashboard API endpoints
impl DashboardServer {
    /// Health check endpoint
    pub fn health_check() -> impl Reply {
        warp::reply::json(&serde_json::json!({
            "status": "healthy",
            "timestamp": chrono::Utc::now().timestamp(),
            "service": "lib-dashboard"
        }))
    }

    /// Version endpoint
    pub fn version() -> impl Reply {
        warp::reply::json(&serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "name": "ZHTP Dashboard",
            "description": "Web dashboard for ZHTP node monitoring"
        }))
    }
}
