fn main() -> anyhow::Result<()> {
    let bind_addr = std::env::var("IOD_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let db_path = std::env::var("IOD_DB_PATH").unwrap_or_else(|_| "iod_simulation.db".to_string());
    iod_core::api::server::run(&bind_addr, &db_path)
}
