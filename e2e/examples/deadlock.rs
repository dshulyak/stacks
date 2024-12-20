//! Note that this example will not finish by itself and almost guaranteed to deadlock.

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::instrument;

#[tokio::main]
async fn main() {
    tracing_stacks::init();

    let state = Arc::new(State {
        first: Mutex::new(0),
        second: Mutex::new(0),
    });
    let handle1 = tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                state.increment_in_order().await;
            }
        }
    });
    let handle2 = tokio::spawn({
        let state = state.clone();
        async move {
            loop {
                state.increment_out_of_order().await;
            }
        }
    });
    handle1.await.expect("no error");
    handle2.await.expect("no error");
}

struct State {
    first: Mutex<u64>,
    second: Mutex<u64>,
}

impl State {
    #[instrument(skip(self))]
    async fn increment_in_order(&self) {
        let mut first = self.first.lock().await;
        let mut second = self.second.lock().await;
        *first += 1;
        *second += 1;
    }

    #[instrument(skip(self))]
    async fn increment_out_of_order(&self) {
        let mut second = self.second.lock().await;
        let mut first = self.first.lock().await;
        *first += 1;
        *second += 1;
    }
}
