// Throwaway spike code for T-009. Not product code, no error handling standards.
//
// A minimal pingora proxy that forwards everything to one backend. The number
// of listeners comes from an environment variable, so the second generation can
// be started with an extra listener and the upgrade path gets exercised.

use async_trait::async_trait;
use pingora::prelude::*;
use pingora::server::configuration::Opt;

struct Forward {
    backend: String,
}

#[async_trait]
impl ProxyHttp for Forward {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(self.backend.as_str(), false, String::new());
        Ok(Box::new(peer))
    }
}

fn main() {
    let backend = std::env::var("SPIKE_BACKEND").unwrap_or_else(|_| "172.28.0.21:80".into());
    // Comma separated. The second generation gets one more address than the
    // first, which is exactly the change that forces a new process.
    let listeners = std::env::var("SPIKE_LISTENERS").unwrap_or_else(|_| "0.0.0.0:6180".into());

    // Opt::parse_args() reads -u/--upgrade and -d/--daemon, which is how the
    // supervisor hands the listening sockets over.
    let mut server = Server::new(Some(Opt::parse_args())).expect("server");
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, Forward { backend });
    for addr in listeners.split(',').filter(|s| !s.is_empty()) {
        service.add_tcp(addr.trim());
    }

    server.add_service(service);
    server.run_forever();
}
