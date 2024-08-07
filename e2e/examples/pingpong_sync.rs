use std::{io::{Write, Read}, net::{TcpListener, TcpStream}, thread::scope};

use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value_t = 10, help = "ping size in KB")]
    ping: u64,
    #[clap(long, default_value_t = 10, help = "pong size in KB")]
    pong: u64,
    #[clap(short, long, default_value_t = 10, help = "number of pings")]
    iters: u64,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let server = TcpListener::bind("127.0.0.1:0")?;
    let addr = server.local_addr()?;
    scope(|s| {
        s.spawn(move || {
            let (mut stream, _) = server.accept().expect("accept");
            let ping = vec![0u8; (opt.ping << 10) as usize];
            let mut pong = vec![0u8; (opt.pong << 10) as usize];
            for _ in 0..opt.iters {
                stream.write_all(ping.as_slice()).expect("ping write");
                stream.read_exact(&mut pong).expect("pong read");
            }
        });
        s.spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect");
            let mut ping = vec![0u8; (opt.ping << 10) as usize];
            let pong = vec![0u8; (opt.pong << 10) as usize];
            for _ in 0..opt.iters {
                client.read_exact(&mut ping).expect("ping read");
                client.write_all(pong.as_slice()).expect("pong write");
            }
        });
    });
    Ok(())
}
