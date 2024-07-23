use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{instrument, level_filters::LevelFilter};
use tracing_subscriber::{prelude::*, Registry};

#[derive(Debug, Deserialize)]
struct JobInput {
    data: String,
    times: u64,
}

#[derive(Debug, Serialize, Clone)]
struct JobResult {
    id: usize,
    result: [u8; 32],
}

static JOB_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

type JobStorage = Arc<Mutex<HashMap<usize, JobResult>>>;

#[instrument(skip_all, fields(amount = input.times))]
async fn post_job(State(storage): State<JobStorage>, Json(input): Json<JobInput>) -> impl IntoResponse {
    let id = JOB_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    // lock is intetionally held for a long time to simulate a slow operation
    let mut storage = storage.lock().unwrap();
    // hash data specified number of times with sha256 and store in result
    let mut hasher = Sha256::new();
    for _ in 0..input.times {
        hasher.update(input.data.as_bytes());
    }
    let mut result = [0; 32];
    result.copy_from_slice(&hasher.finalize());

    let job_result = JobResult { id, result };
    storage.insert(id, job_result.clone());
    Json(job_result)
}

#[instrument(skip_all, fields(id = %id))]
async fn get_job(
    State(storage): State<JobStorage>,
    axum::extract::Path(id): axum::extract::Path<usize>,
) -> impl IntoResponse {
    let val = storage.lock().unwrap().get(&id).cloned();
    match val {
        Some(result) => Json(result.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "127.0.0.1:8000")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let registry = Registry::default()
        .with(
            tracing_past::PastSubscriber {}.with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        );
    tracing::dispatcher::set_global_default(registry.into()).expect("failed to set global default subscriber");

    let opt = Opt::parse();
    let storage: JobStorage = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/jobs", post(post_job))
        .route("/jobs/:id", get(get_job))
        .with_state(storage);
    let listener = tokio::net::TcpListener::bind(&opt.listen).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr()?);
    let server = axum::serve(listener, app);
    server.await?;
    Ok(())
}
