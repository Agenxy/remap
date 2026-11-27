// SPDX-License-Identifier: GPL-3.0-or-later
//! Binding failures name their cause and the fix; the crate prints nothing.

use std::net::Ipv4Addr;

use remap_protocol::{ControlClient, Surface};
use remap_web::{WebOptions, WebServer};
use tokio::net::TcpListener;

use crate::support::TestResult;

fn client() -> ControlClient {
    ControlClient::new("/nonexistent/remap.sock", Surface::Cli, "test")
}

#[tokio::test]
async fn a_taken_port_is_web_port_in_use() -> TestResult {
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = taken.local_addr()?.port();
    let refused = WebServer::bind(client(), WebOptions { port, name: None }).await;
    let diagnostic = refused.err().ok_or("the taken port was bound")?;
    assert_eq!(diagnostic.code, "web-port-in-use");
    assert!(diagnostic.message.contains(&port.to_string()));
    assert!(diagnostic.hint.is_some_and(|hint| hint.contains("--port")));
    Ok(())
}

#[tokio::test]
async fn a_chosen_free_port_is_used() -> TestResult {
    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let server = WebServer::bind(client(), WebOptions { port, name: None }).await?;
    assert_eq!(server.local_addr().port(), port);
    assert!(
        server
            .url()
            .starts_with(&format!("http://127.0.0.1:{port}/#token="))
    );
    let url = server.url();
    let token = url.split_once("#token=").map_or("", |(_, token)| token);
    assert_eq!(token.len(), 64);
    assert!(
        !format!("{server:?}").contains(token),
        "Debug shows the token"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_name_is_web_name_invalid() -> TestResult {
    for name in ["http://remap.lab", "remap.lab:80", "*.lab", "", "127.0.0.1"] {
        let options = WebOptions {
            port: 0,
            name: Some(name.to_owned()),
        };
        let diagnostic = WebServer::bind(client(), options)
            .await
            .err()
            .ok_or("an invalid name was accepted")?;
        assert_eq!(diagnostic.code, "web-name-invalid", "{name}");
        assert!(diagnostic.hint.is_some());
    }
    Ok(())
}

#[test]
fn the_crate_never_writes_to_standard_output_or_error() -> TestResult {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(source)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        for forbidden in ["print!", "println!", "eprint", "dbg!", "tracing::", "log::"] {
            assert!(
                !text.contains(forbidden),
                "{} uses {forbidden}",
                path.display()
            );
        }
    }
    Ok(())
}
