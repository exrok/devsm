#[path = "e2e/e2e_bench.rs"]
mod e2e_bench;
#[path = "e2e/e2e_cli.rs"]
mod e2e_cli;
#[cfg(feature = "fuzz")]
#[path = "e2e/e2e_fuzz_time.rs"]
mod e2e_fuzz_time;
#[path = "e2e/e2e_test_app.rs"]
mod e2e_test_app;
#[path = "e2e/e2e_tui.rs"]
mod e2e_tui;
#[path = "e2e/harness.rs"]
mod harness;
#[path = "../../devsm/src/rpc.rs"]
mod rpc;
