//! Calls the sample's `create_pool` and exits 0 only when that session is using TLS.
//! The checker is a test harness: it does not change the application.

#[path = "../../../backend/src/postgres.rs"]
mod app_postgres;

#[tokio::main]
async fn main() {
    let pool = app_postgres::create_pool();
    let client = pool.get().await.expect("couldn't get postgres client");
    let ssl: bool = client
        .query_one(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .expect("couldn't read pg_stat_ssl")
        .get(0);
    if !ssl {
        eprintln!("application pool session is not using TLS");
        std::process::exit(1);
    }
}
