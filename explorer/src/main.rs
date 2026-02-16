use gloo_net::http::Request;
use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StatsResponse {
    status: String,
    latest_height: u64,
    latest_block_time: Option<u64>,
    total_transactions: u64,
    avg_block_time_secs: Option<u64>,
    total_supply: u64,
    total_ubi_distributed: u64,
    active_validators: usize,
    mempool_size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BlockSummary {
    height: u64,
    hash: String,
    timestamp: u64,
    transaction_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BlocksResponse {
    status: String,
    blocks: Vec<BlockSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TxSummary {
    hash: String,
    transaction_type: String,
    fee: u64,
    timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TransactionsResponse {
    status: String,
    transactions: Vec<TxSummary>,
}

// --- Detail response types ---

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BlockDetailResponse {
    status: String,
    height: u64,
    hash: String,
    previous_hash: String,
    timestamp: u64,
    transaction_count: usize,
    merkle_root: String,
    nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TransactionInfo {
    hash: String,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    transaction_type: String,
    timestamp: u64,
    size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TransactionDetailResponse {
    status: String,
    transaction: Option<TransactionInfo>,
    block_height: Option<u64>,
    confirmations: Option<u64>,
    in_mempool: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SearchResponse {
    status: String,
    query: String,
    result_type: Option<String>,
    result: Option<serde_json::Value>,
    message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IdentityResponse {
    status: String,
    did: Option<String>,
    display_name: Option<String>,
    identity_type: Option<String>,
    registration_fee: Option<u64>,
    created_at: Option<u64>,
    controlled_nodes: Option<Vec<String>>,
    owned_wallets: Option<Vec<String>>,
    message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WalletInfo {
    wallet_id: String,
    wallet_name: Option<String>,
    wallet_type: Option<String>,
    alias: Option<String>,
    owner_identity_id: Option<String>,
    capabilities: Option<Vec<String>>,
    created_at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WalletsResponse {
    status: String,
    wallet_count: usize,
    wallets: Vec<WalletInfo>,
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> Option<T> {
    Request::get(url).send().await.ok()?.json::<T>().await.ok()
}

#[component]
fn App() -> impl IntoView {
    view! {
        <Router>
            <div class="app">
                <Header />
                <main class="main">
                    <Routes>
                        <Route path="" view=Dashboard />
                        <Route path="block/:hash" view=BlockView />
                        <Route path="tx/:hash" view=TxView />
                        <Route path="wallet/:id" view=WalletView />
                        <Route path="did/:id" view=IdentityView />
                        <Route path="search" view=SearchView />
                    </Routes>
                </main>
                <Footer />
            </div>
        </Router>
    }
}

#[component]
fn Header() -> impl IntoView {
    view! {
        <header class="header">
            <div class="brand">
                <div class="brand-title">"Sovereign Explorer"</div>
                <div class="brand-sub">"Testnet — Web4 Citizen"</div>
            </div>
            <nav class="nav">
                <A href="/">"Dashboard"</A>
                <A href="/search">"Search"</A>
            </nav>
        </header>
    }
}

#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer class="footer">
            "Sovereign Network · Explorer served from root domain"
        </footer>
    }
}

#[component]
fn Dashboard() -> impl IntoView {
    let stats = create_resource(|| (), |_| async move { fetch_json::<StatsResponse>("/api/v1/blockchain/stats").await });
    let blocks = create_resource(|| (), |_| async move { fetch_json::<BlocksResponse>("/api/v1/blockchain/blocks?limit=6").await });
    let txs = create_resource(|| (), |_| async move { fetch_json::<TransactionsResponse>("/api/v1/blockchain/transactions?limit=6").await });

    view! {
        <section class="hero">
            <h1>"Block Explorer"</h1>
            <p>
                "Public ledger visibility for SOV transfers, token activity, and citizen economics. "
                "Commitment values are displayed where amounts are private."
            </p>
            <SearchBar />
        </section>

        <section class="grid">
            <div class="card">
                <h3>"Network Stats"</h3>
                {move || match stats.get() {
                    None => view! { <p>"Loading stats..."</p> }.into_view(),
                    Some(None) => view! { <p>"Stats unavailable"</p> }.into_view(),
                    Some(Some(data)) => view! {
                        <>
                            <p><span class="badge">"Height"</span> {data.latest_height}</p>
                            <p><span class="badge">"Total TX"</span> {data.total_transactions}</p>
                            <p><span class="badge">"Supply"</span> {data.total_supply}</p>
                            <p><span class="badge">"UBI Distributed"</span> {data.total_ubi_distributed}</p>
                            <p><span class="badge">"Active Validators"</span> {data.active_validators}</p>
                            <p><span class="badge">"Mempool"</span> {data.mempool_size}</p>
                            <p><span class="badge">"Avg Block Time"</span> {data.avg_block_time_secs.unwrap_or(0)} "s"</p>
                        </>
                    }.into_view(),
                }}
            </div>

            <div class="card">
                <h3>"Latest Blocks"</h3>
                {move || match blocks.get() {
                    None => view! { <p>"Loading blocks..."</p> }.into_view(),
                    Some(None) => view! { <p>"Blocks unavailable"</p> }.into_view(),
                    Some(Some(data)) => view! {
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>"Height"</th>
                                    <th>"Txs"</th>
                                    <th>"Hash"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.blocks.into_iter().map(|b| view! {
                                    <tr>
                                        <td>{b.height}</td>
                                        <td>{b.transaction_count}</td>
                                        <td><A href=format!("/block/{}", b.hash)>{short_hash(&b.hash)}</A></td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    }.into_view(),
                }}
            </div>

            <div class="card">
                <h3>"Latest Transactions"</h3>
                {move || match txs.get() {
                    None => view! { <p>"Loading transactions..."</p> }.into_view(),
                    Some(None) => view! { <p>"Transactions unavailable"</p> }.into_view(),
                    Some(Some(data)) => view! {
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>"Hash"</th>
                                    <th>"Type"</th>
                                    <th>"Fee"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.transactions.into_iter().map(|tx| view! {
                                    <tr>
                                        <td><A href=format!("/tx/{}", tx.hash)>{short_hash(&tx.hash)}</A></td>
                                        <td>{tx.transaction_type}</td>
                                        <td>{tx.fee}</td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    }.into_view(),
                }}
            </div>
        </section>
    }
}

#[component]
fn SearchBar() -> impl IntoView {
    let query = create_node_ref::<leptos::html::Input>();
    let navigate = use_navigate();

    let on_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if let Some(input) = query.get() {
            let value = input.value();
            if !value.trim().is_empty() {
                let _ = navigate(&format!("/search?q={}", value.trim()), Default::default());
            }
        }
    };

    view! {
        <form class="search" on:submit=on_submit>
            <input
                type="text"
                placeholder="tx hash, block hash, wal_..., did_..."
                node_ref=query
            />
            <button type="submit">"Search"</button>
        </form>
    }
}

#[component]
fn SearchView() -> impl IntoView {
    let params = use_query_map();
    let q = move || params.with(|p| p.get("q").cloned().unwrap_or_default());

    let search = create_resource(
        move || q(),
        |query| async move {
            if query.is_empty() {
                return None;
            }
            fetch_json::<SearchResponse>(&format!("/api/v1/blockchain/search?q={}", query)).await
        },
    );

    view! {
        <section class="card">
            <h3>"Search"</h3>
            <SearchBar />
            {move || {
                let query = q();
                if query.is_empty() {
                    return view! { <p class="dim">"Enter a tx hash, block hash, wallet ID, or DID to search."</p> }.into_view();
                }
                match search.get() {
                    None => view! { <p>"Searching..."</p> }.into_view(),
                    Some(None) => view! { <p>"Search failed — node may be unreachable."</p> }.into_view(),
                    Some(Some(data)) => {
                        if let Some(ref msg) = data.message {
                            if data.result_type.is_none() {
                                return view! { <p>{msg.clone()}</p> }.into_view();
                            }
                        }
                        match data.result_type.as_deref() {
                            Some("block") => view! {
                                <p>"Found block:"</p>
                                <p><A href=format!("/block/{}", data.query)>"View block " {short_hash(&data.query)}</A></p>
                            }.into_view(),
                            Some("transaction") => view! {
                                <p>"Found transaction:"</p>
                                <p><A href=format!("/tx/{}", data.query)>"View transaction " {short_hash(&data.query)}</A></p>
                            }.into_view(),
                            Some("identity") => view! {
                                <p>"Found identity:"</p>
                                <p><A href=format!("/did/{}", data.query)>"View identity " {short_hash(&data.query)}</A></p>
                            }.into_view(),
                            Some("wallet") => view! {
                                <p>"Found wallet:"</p>
                                <p><A href=format!("/wallet/{}", data.query)>"View wallet " {short_hash(&data.query)}</A></p>
                            }.into_view(),
                            Some(kind) => view! {
                                <p>"Found " {kind.to_string()} " for query: " {data.query.clone()}</p>
                            }.into_view(),
                            None => view! {
                                <p>"No results for: " {data.query.clone()}</p>
                            }.into_view(),
                        }
                    }
                }
            }}
        </section>
    }
}

#[component]
fn BlockView() -> impl IntoView {
    let params = use_params_map();
    let hash = move || params.with(|p| p.get("hash").cloned().unwrap_or_default());

    let block = create_resource(
        move || hash(),
        |h| async move {
            if h.is_empty() { return None; }
            fetch_json::<BlockDetailResponse>(&format!("/api/v1/blockchain/block/{}", h)).await
        },
    );

    view! {
        <section class="card">
            <h3>"Block Details"</h3>
            <p class="dim"><A href="/">"< Back to Dashboard"</A></p>
            {move || match block.get() {
                None => view! { <p>"Loading block..."</p> }.into_view(),
                Some(None) => view! { <p>"Block not found or node unreachable."</p> }.into_view(),
                Some(Some(data)) => view! {
                    <div class="detail-grid">
                        <p><span class="badge">"Height"</span> {data.height}</p>
                        <p><span class="badge">"Hash"</span> <span class="mono">{data.hash}</span></p>
                        <p><span class="badge">"Previous"</span> <span class="mono">{short_hash(&data.previous_hash)}</span></p>
                        <p><span class="badge">"Timestamp"</span> {format_timestamp(data.timestamp)}</p>
                        <p><span class="badge">"Transactions"</span> {data.transaction_count}</p>
                        <p><span class="badge">"Merkle Root"</span> <span class="mono">{short_hash(&data.merkle_root)}</span></p>
                        <p><span class="badge">"Nonce"</span> {data.nonce}</p>
                    </div>
                }.into_view(),
            }}
        </section>
    }
}

#[component]
fn TxView() -> impl IntoView {
    let params = use_params_map();
    let hash = move || params.with(|p| p.get("hash").cloned().unwrap_or_default());

    let tx = create_resource(
        move || hash(),
        |h| async move {
            if h.is_empty() { return None; }
            fetch_json::<TransactionDetailResponse>(&format!("/api/v1/blockchain/transaction/{}", h)).await
        },
    );

    view! {
        <section class="card">
            <h3>"Transaction Details"</h3>
            <p class="dim"><A href="/">"< Back to Dashboard"</A></p>
            {move || match tx.get() {
                None => view! { <p>"Loading transaction..."</p> }.into_view(),
                Some(None) => view! { <p>"Transaction not found or node unreachable."</p> }.into_view(),
                Some(Some(data)) => {
                    match data.transaction {
                        None => view! { <p>"Transaction data unavailable."</p> }.into_view(),
                        Some(info) => view! {
                            <div class="detail-grid">
                                <p><span class="badge">"Hash"</span> <span class="mono">{info.hash}</span></p>
                                <p><span class="badge">"Type"</span> {info.transaction_type}</p>
                                <p><span class="badge">"From"</span> <span class="mono">{short_hash(&info.from)}</span></p>
                                <p><span class="badge">"To"</span> <span class="mono">{short_hash(&info.to)}</span></p>
                                <p><span class="badge">"Amount"</span> {info.amount}</p>
                                <p><span class="badge">"Fee"</span> {info.fee}</p>
                                <p><span class="badge">"Timestamp"</span> {format_timestamp(info.timestamp)}</p>
                                <p><span class="badge">"Size"</span> {info.size} " bytes"</p>
                                {data.block_height.map(|h| view! {
                                    <p><span class="badge">"Block Height"</span> {h}</p>
                                })}
                                {data.confirmations.map(|c| view! {
                                    <p><span class="badge">"Confirmations"</span> {c}</p>
                                })}
                                <p><span class="badge">"In Mempool"</span> {if data.in_mempool { "Yes" } else { "No" }}</p>
                            </div>
                        }.into_view(),
                    }
                }
            }}
        </section>
    }
}

#[component]
fn WalletView() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with(|p| p.get("id").cloned().unwrap_or_default());

    let wallets = create_resource(
        move || id(),
        |wallet_id| async move {
            if wallet_id.is_empty() { return None; }
            fetch_json::<WalletsResponse>(&format!("/api/v1/blockchain/wallets?owner_identity={}", wallet_id)).await
        },
    );

    view! {
        <section class="card">
            <h3>"Wallet Details"</h3>
            <p class="dim"><A href="/">"< Back to Dashboard"</A></p>
            <p><span class="badge">"Owner"</span> <span class="mono">{id}</span></p>
            {move || match wallets.get() {
                None => view! { <p>"Loading wallets..."</p> }.into_view(),
                Some(None) => view! { <p>"Could not load wallets — node may be unreachable."</p> }.into_view(),
                Some(Some(data)) => {
                    if data.wallets.is_empty() {
                        return view! { <p>"No wallets found for this identity."</p> }.into_view();
                    }
                    view! {
                        <p>{data.wallet_count} " wallet(s) found"</p>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>"Wallet ID"</th>
                                    <th>"Name"</th>
                                    <th>"Type"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.wallets.into_iter().map(|w| view! {
                                    <tr>
                                        <td><span class="mono">{short_hash(&w.wallet_id)}</span></td>
                                        <td>{w.wallet_name.unwrap_or_else(|| "—".to_string())}</td>
                                        <td>{w.wallet_type.unwrap_or_else(|| "—".to_string())}</td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    }.into_view()
                }
            }}
        </section>
    }
}

#[component]
fn IdentityView() -> impl IntoView {
    let params = use_params_map();
    let id = move || params.with(|p| p.get("id").cloned().unwrap_or_default());

    let identity = create_resource(
        move || id(),
        |did| async move {
            if did.is_empty() { return None; }
            fetch_json::<IdentityResponse>(&format!("/api/v1/blockchain/identities/{}", did)).await
        },
    );

    view! {
        <section class="card">
            <h3>"Identity Details"</h3>
            <p class="dim"><A href="/">"< Back to Dashboard"</A></p>
            {move || match identity.get() {
                None => view! { <p>"Loading identity..."</p> }.into_view(),
                Some(None) => view! { <p>"Identity not found or node unreachable."</p> }.into_view(),
                Some(Some(data)) => {
                    if data.status == "identity_not_found" {
                        return view! { <p>{data.message.unwrap_or_else(|| "Identity not found.".to_string())}</p> }.into_view();
                    }
                    let did = data.did.unwrap_or_default();
                    let display_name = data.display_name.unwrap_or_else(|| "—".to_string());
                    let identity_type = data.identity_type.unwrap_or_else(|| "—".to_string());
                    let reg_fee = data.registration_fee;
                    let created = data.created_at;
                    let wallets = data.owned_wallets.unwrap_or_default();
                    let nodes = data.controlled_nodes.unwrap_or_default();
                    view! {
                        <div class="detail-grid">
                            <p><span class="badge">"DID"</span> <span class="mono">{did}</span></p>
                            <p><span class="badge">"Display Name"</span> {display_name}</p>
                            <p><span class="badge">"Type"</span> {identity_type}</p>
                            {reg_fee.map(|fee| view! {
                                <p><span class="badge">"Registration Fee"</span> {fee}</p>
                            })}
                            {created.map(|ts| view! {
                                <p><span class="badge">"Created"</span> {format_timestamp(ts)}</p>
                            })}
                            {if wallets.is_empty() {
                                view! { <p class="dim">"No wallets"</p> }.into_view()
                            } else {
                                view! {
                                    <p><span class="badge">"Wallets"</span></p>
                                    <ul>
                                        {wallets.into_iter().map(|w| {
                                            let href = format!("/wallet/{}", w);
                                            let label = short_hash(&w);
                                            view! { <li><A href=href>{label}</A></li> }
                                        }).collect_view()}
                                    </ul>
                                }.into_view()
                            }}
                            {if nodes.is_empty() {
                                view! { <p class="dim">"No controlled nodes"</p> }.into_view()
                            } else {
                                view! {
                                    <p><span class="badge">"Controlled Nodes"</span></p>
                                    <ul>
                                        {nodes.into_iter().map(|n| {
                                            let label = short_hash(&n);
                                            view! { <li><span class="mono">{label}</span></li> }
                                        }).collect_view()}
                                    </ul>
                                }.into_view()
                            }}
                        </div>
                    }.into_view()
                }
            }}
        </section>
    }
}

fn short_hash(hash: &str) -> String {
    if hash.len() <= 12 {
        hash.to_string()
    } else {
        format!("{}…{}", &hash[..6], &hash[hash.len() - 4..])
    }
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "—".to_string();
    }
    // Simple timestamp display — WASM doesn't have chrono, just show epoch seconds
    // with a human-readable relative indicator
    let now = js_sys::Date::now() as u64 / 1000;
    let diff = now.saturating_sub(ts);
    let time_ago = if diff < 60 {
        format!("{}s ago", diff)
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    };
    format!("{} ({})", ts, time_ago)
}

fn main() {
    mount_to_body(App);
}
