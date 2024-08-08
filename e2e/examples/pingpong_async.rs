use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value_t = 10, help = "ping size in KB")]
    ping: u64,
    #[clap(long, default_value_t = 10, help = "pong size in KB")]
    pong: u64,
    #[clap(short, long, default_value_t = 10, help = "number of pings")]
    iters: u64,
}

#[tokio::main]
async fn main() {
    tracing_stacks::init();

    let opt = Opt::parse();
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = server.local_addr().expect("local_addr");
    let t1 = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.expect("accept");
        let ping = vec![0u8; (opt.ping << 10) as usize];
        let mut pong = vec![0u8; (opt.pong << 10) as usize];
        async {
            for _ in 0..opt.iters {
                stream.write_all(ping.as_slice()).await.expect("ping write");
                stream.read_exact(&mut pong).await.expect("pong read");
            }
        }
        .instrument(tracing::info_span!("ping"))
        .await;
    });
    let t2 = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut ping = vec![0u8; (opt.ping << 10) as usize];
        let pong = vec![0u8; (opt.pong << 10) as usize];
        async {
            for _ in 0..opt.iters {
                client.read_exact(&mut ping).await.expect("ping read");
                client.write_all(pong.as_slice()).await.expect("pong write");
            }
        }
        .instrument(tracing::info_span!("pong"))
        .await;
    });
    t1.await.expect("t1");
    t2.await.expect("t2");
}
