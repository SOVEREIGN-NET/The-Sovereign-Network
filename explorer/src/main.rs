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

    view! {
        <section class="card">
            <h3>"Search"</h3>
            <p>"Query: " {q}</p>
            <p>"Results are returned by /api/v1/blockchain/search. "
                "If ambiguous, prefix with tx_, blk_, wal_, or did_."</p>
        </section>
    }
}

#[component]
fn BlockView() -> impl IntoView {
    view! {
        <section class="card">
            <h3>"Block Details"</h3>
            <p>"Block detail view is loading..."</p>
        </section>
    }
}

#[component]
fn TxView() -> impl IntoView {
    view! {
        <section class="card">
            <h3>"Transaction Details"</h3>
            <p>"Transaction detail view is loading..."</p>
        </section>
    }
}

#[component]
fn WalletView() -> impl IntoView {
    view! {
        <section class="card">
            <h3>"Wallet Details"</h3>
            <p>"Wallet lookup view is loading..."</p>
        </section>
    }
}

#[component]
fn IdentityView() -> impl IntoView {
    view! {
        <section class="card">
            <h3>"Identity Details"</h3>
            <p>"Identity/DID lookup view is loading..."</p>
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

fn main() {
    mount_to_body(App);
}
