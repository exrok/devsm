use super::*;
use crate::rpc::DecodeResult;
use crate::rpc::DecodingState;
use crate::workspace::FunctionGlobalAction;
use jsony_value::ValueMap;

pub struct ClientMessage<'a> {
    pub correlation: u16,
    pub kind: RpcMessageKind,
    #[allow(unused)]
    pub one_shot: bool,
    pub ws_data: &'a [u8],
    pub payload: &'a [u8],
}

struct RpcClientStream {
    client_index: ClientIndex,
    termination_reason: Option<SocketTerminationReason>,
    state: DecodingState,
    buffer: Vec<u8>,
}

impl RpcClientStream {
    fn client_requests_termination(&mut self) {
        self.termination_reason = Some(SocketTerminationReason::ClientRequestedTerminate);
    }
    fn next<'b>(&'b mut self) -> Option<ClientMessage<'b>> {
        loop {
            match self.state.decode(&self.buffer) {
                DecodeResult::Message { kind, correlation, one_shot, payload, ws_data } => {
                    return Some(ClientMessage { correlation, kind, one_shot, ws_data, payload });
                }
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => break,
                DecodeResult::Error(e) => {
                    kvlog::error!("Test run client protocol decode error", ?e, index = self.client_index);
                    self.termination_reason = Some(SocketTerminationReason::ProtocolError);
                    break;
                }
            }
        }
        None
    }
}
impl ClientEntry {
    fn rpc_stream(&mut self, pool: &mut Vec<Vec<u8>>, client_index: ClientIndex) -> RpcClientStream {
        let (state, buffer) =
            self.partial_rpc_read.take().unwrap_or_else(|| (DecodingState::default(), pool.pop().unwrap_or_default()));
        let mut reader = RpcClientStream { client_index, termination_reason: None, state, buffer };
        loop {
            match try_read(self.socket.as_raw_fd(), &mut reader.buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    reader.termination_reason = Some(SocketTerminationReason::Eof);
                    break;
                }
                ReadResult::Done => break,
                ReadResult::WouldBlock => break,
                ReadResult::OtherError(err) => {
                    kvlog::error!("Test run client read failed", ?err, index = reader.client_index);
                    reader.termination_reason = Some(SocketTerminationReason::ReadError);
                    break;
                }
            }
        }
        reader
    }
}

fn restart_selected_from_clients(clients: &Slab<ClientEntry>, ws: &WorkspaceEntry) -> Result<(), &'static str> {
    let ws_index = ws.handle.workspace_id;
    for (_, client) in clients {
        if client.workspace != ws_index {
            continue;
        }
        let selected = client.channel.selected.load(std::sync::atomic::Ordering::Relaxed);
        if selected & SELECTED_META_GROUP_FLAG != 0 {
            let kind = match selected {
                SELECTED_META_GROUP_TESTS => TaskKind::Test,
                SELECTED_META_GROUP_ACTIONS => TaskKind::Action,
                _ => return Err("invalid meta-group selection"),
            };
            let ws_state = ws.handle.state();
            let jobs = ws_state.jobs_by_kind(kind);
            let Some(&last_ji) = jobs.last() else {
                return Err("no jobs in selected meta-group");
            };
            let job = &ws_state[last_ji];
            let bti = job.log_group.base_task_index();
            let params = job.spawn_params.clone();
            let profile = job.spawn_profile.clone();
            drop(ws_state);
            ws.handle.restart_task(bti, params, &profile);
        } else {
            let bti = workspace::BaseTaskIndex(selected as u32);
            let ws_state = ws.handle.state();
            let Some(bt) = ws_state.base_tasks.get(bti.idx()) else {
                return Err("selected task no longer exists");
            };
            if let Some(&last_ji) = bt.jobs.all().last() {
                let job = &ws_state[last_ji];
                let params = job.spawn_params.clone();
                let profile = job.spawn_profile.clone();
                drop(ws_state);
                ws.handle.restart_task(bti, params, &profile);
            } else {
                drop(ws_state);
                ws.handle.restart_task(bti, ValueMap::new(), "");
            }
        }
        return Ok(());
    }
    Err("no active TUI session")
}
fn handle_test_run_client_read(rpc_reader: &mut RpcClientStream) {
    while let Some(message) = rpc_reader.next() {
        match message.kind {
            RpcMessageKind::Terminate => rpc_reader.client_requests_termination(),
            _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
        }
    }
}

fn handle_tui_client_read(rpc_reader: &mut RpcClientStream, client: &mut ClientEntry) {
    let mut wake = false;
    while let Some(message) = rpc_reader.next() {
        match message.kind {
            RpcMessageKind::Resize => {
                client.channel.state.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                wake = true;
            }
            RpcMessageKind::Terminate => rpc_reader.client_requests_termination(),
            _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
        }
    }
    if wake {
        let _ = client.channel.wake();
    }
}

fn handle_run_client_read(rpc_reader: &mut RpcClientStream, log_group: LogGroup, state: &mut State) {
    let mut kill_task = false;
    while let Some(message) = rpc_reader.next() {
        match message.kind {
            RpcMessageKind::Terminate => {
                rpc_reader.client_requests_termination();
                kill_task = true;
            }
            _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
        }
    }

    if kill_task {
        for (_, process) in &state.processes {
            if process.log_group == log_group {
                let child_pid = process.child.id();
                let pgid = -(child_pid as i32);
                unsafe {
                    libc::kill(pgid, libc::SIGINT);
                }
                break;
            }
        }
    }
}

fn handle_logs_client_read(rpc_reader: &mut RpcClientStream) {
    while let Some(message) = rpc_reader.next() {
        match message.kind {
            RpcMessageKind::Terminate => {
                rpc_reader.client_requests_termination();
            }
            _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
        }
    }
}

fn resolve_workspace_from_header(
    state: &mut State,
    ws_data: &[u8],
    correlation: u16,
    encoder: &mut crate::rpc::Encoder,
) -> Option<WorkspaceIndex> {
    use crate::rpc::{CommandBody, CommandResponse, RpcMessageKind, WorkspaceRef};

    if ws_data.is_empty() {
        encoder.encode_response(
            RpcMessageKind::CommandAck,
            correlation,
            &CommandResponse { workspace_id: 0, body: CommandBody::Error("Workspace required".into()) },
        );
        return None;
    }

    let ws_ref = match jsony::from_binary::<WorkspaceRef>(ws_data) {
        Ok(r) => r,
        Err(_) => {
            encoder.encode_response(
                RpcMessageKind::CommandAck,
                correlation,
                &CommandResponse { workspace_id: 0, body: CommandBody::Error("Invalid workspace ref".into()) },
            );
            return None;
        }
    };

    match resolve_workspace(state, &ws_ref) {
        Ok(idx) => Some(idx),
        Err(e) => {
            encoder.encode_response(
                RpcMessageKind::CommandAck,
                correlation,
                &CommandResponse { workspace_id: 0, body: CommandBody::Error(e.into()) },
            );
            None
        }
    }
}

fn resolve_workspace(state: &mut State, ws_ref: &crate::rpc::WorkspaceRef) -> Result<WorkspaceIndex, String> {
    match ws_ref {
        crate::rpc::WorkspaceRef::Id(id) => {
            if (*id as usize) < state.workspaces.len() {
                Ok(*id)
            } else {
                Err(format!("Invalid workspace ID: {}", id))
            }
        }
        crate::rpc::WorkspaceRef::Path { config } => {
            // todo maybe we shouldn't just create that path
            state.get_or_create_workspace_index(config.to_path_buf()).map_err(|e| e.to_string())
        }
    }
}

fn handle_rpc_message(
    client_index: ClientIndex,
    clients: &mut Slab<ClientEntry>,
    state: &mut State,
    kind: RpcMessageKind,
    correlation: u16,
    ws_data: &[u8],
    payload: &[u8],
    encoder: &mut crate::rpc::Encoder,
) {
    match kind {
        RpcMessageKind::Subscribe => {
            let Ok(filter) = jsony::from_binary::<crate::rpc::SubscriptionFilter>(payload) else {
                encoder.encode_response(
                    RpcMessageKind::ErrorResponse,
                    correlation,
                    &crate::rpc::ErrorResponsePayload { code: 1, message: "Invalid subscription filter".into() },
                );
                return;
            };
            let ClientKind::Rpc { subscriptions } = &mut clients[client_index as usize].kind else { return };
            subscriptions.job_status = filter.job_status;
            subscriptions.job_exits = filter.job_exits;
            encoder.encode_response(
                RpcMessageKind::SubscribeAck,
                correlation,
                &crate::rpc::SubscribeAck { success: true },
            );
            return;
        }
        RpcMessageKind::RunTask => {
            let Some(ws_index) = resolve_workspace_from_header(state, ws_data, correlation, encoder) else {
                return;
            };
            let Ok(req) = jsony::from_binary::<crate::rpc::RunTaskRequest>(payload) else {
                encoder.encode_response(
                    RpcMessageKind::ErrorResponse,
                    correlation,
                    &crate::rpc::ErrorResponsePayload { code: 2, message: "Invalid run task request".into() },
                );
                return;
            };
            let params: ValueMap = jsony::from_binary(req.params).unwrap_or_else(|_| ValueMap::new());
            let ws = &state.workspaces[ws_index as usize];
            let mut state = ws.handle.state.write().unwrap();
            let Some(base_index) = state.base_index_by_name(req.task_name) else {
                drop(state);
                encoder.encode_response(
                    RpcMessageKind::RunTaskAck,
                    correlation,
                    &crate::rpc::RunTaskResponse {
                        success: false,
                        job_index: None,
                        error: Some(format!("Task '{}' not found", req.task_name).into()),
                    },
                );
                return;
            };
            drop(state);

            ws.handle.restart_task(base_index, params, req.profile);

            let ws_state = ws.handle.state.read().unwrap();
            let bt = &ws_state.base_tasks[base_index.idx()];
            let job_index = bt.jobs.all().last().map(|ji| ji.as_u32());

            encoder.encode_response(
                RpcMessageKind::RunTaskAck,
                correlation,
                &crate::rpc::RunTaskResponse { success: true, job_index, error: None },
            );
        }
        RpcMessageKind::Terminate => {
            encoder.encode_empty(RpcMessageKind::TerminateAck, correlation);
        }
        RpcMessageKind::OpenWorkspace => {
            encoder.encode_response(
                RpcMessageKind::OpenWorkspaceAck,
                correlation,
                &crate::rpc::OpenWorkspaceResponse { success: true, error: None },
            );
        }
        _ => (),
    }

    let Some(ws_index) = resolve_workspace_from_header(state, ws_data, correlation, encoder) else {
        return;
    };
    let ws = &mut state.workspaces[ws_index as usize];
    let body = match kind {
        RpcMessageKind::SpawnTask => handle_rpc_restart_task(ws, payload),
        RpcMessageKind::KillTask => handle_rpc_kill_task(ws, payload),
        RpcMessageKind::RerunTests => handle_rpc_rerun_tests(ws, payload),
        RpcMessageKind::CallFunction => handle_rpc_call_function(clients, ws, payload),
        RpcMessageKind::GetLoggedRustPanics => handle_rpc_get_logged_rust_panics(ws, payload),
        _ => {
            kvlog::warn!("Unexpected RPC message kind from client", ?kind);
            encoder.encode_response(
                RpcMessageKind::CommandAck,
                correlation,
                &crate::rpc::CommandResponse {
                    workspace_id: 0,
                    body: CommandBody::Error("Unsupported command".into()),
                },
            );
            return;
        }
    };
    encoder.encode_response(
        RpcMessageKind::CommandAck,
        correlation,
        &crate::rpc::CommandResponse { workspace_id: ws_index, body },
    );
}

fn handle_rpc_restart_task(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(req) = jsony::from_binary::<rpc::SpawnTaskRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    let params: ValueMap = jsony::from_binary(req.params).unwrap_or_else(|_| ValueMap::new());

    let result = if req.as_test {
        ws.handle.spawn_task_as_test(req.task_name, params, req.profile).map(|()| None)
    } else {
        ws.handle.spawn_task_by_name_cached(req.task_name, params, req.profile, req.cached)
    };

    match result {
        Ok(None) => CommandBody::Empty,
        Ok(Some(msg)) => CommandBody::Message(msg.into()),
        Err(e) => CommandBody::Error(e.into()),
    }
}

fn handle_rpc_kill_task(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(req) = jsony::from_binary::<rpc::KillTaskRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    match ws.handle.terminate_task_by_name(req.task_name) {
        Ok(msg) => CommandBody::Message(msg.into()),
        Err(e) => CommandBody::Error(e.into()),
    }
}

fn handle_rpc_rerun_tests(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(req) = jsony::from_binary::<rpc::RerunTestsRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    match ws.handle.rerun_test_group(req.only_failed) {
        Ok(_) => CommandBody::Message("Rerunning tests".into()),
        Err(e) => CommandBody::Error(e.to_string().into()),
    }
}

fn handle_rpc_call_function(clients: &Slab<ClientEntry>, ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(req) = jsony::from_binary::<rpc::CallFunctionRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    match ws.handle.call_function(req.function_name) {
        Ok(None) => CommandBody::Message("Ok".into()),
        Ok(Some(FunctionGlobalAction::RestartSelected)) => match restart_selected_from_clients(clients, ws) {
            Ok(()) => CommandBody::Message("Restarted selected task".into()),
            Err(e) => CommandBody::Error(e.into()),
        },
        Err(e) => CommandBody::Error(e.into()),
    }
}

fn handle_rpc_get_logged_rust_panics(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(_) = jsony::from_binary::<rpc::GetLoggedRustPanicsRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    let response = jsony::to_json(&ws.handle.logged_rust_panics());
    CommandBody::Message(response.into())
}

fn handle_self_logs_client_read(rpc_reader: &mut RpcClientStream) {
    while let Some(message) = rpc_reader.next() {
        match message.kind {
            _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
        }
    }
}

impl EventLoop {
    pub fn handle_client_rpc_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            kvlog::error!("Read for missing client", index = client_index as usize);
            return;
        };
        let mut rpc_stream = client.rpc_stream(&mut self.buffer_pool, client_index);
        // once we refactor the event loop to split up the components we'll be able to simply this even more
        match &client.kind {
            ClientKind::Rpc { .. } => {
                let mut encoder = crate::rpc::Encoder::new();
                while let Some(ClientMessage { kind, correlation, ws_data, payload, .. }) = rpc_stream.next() {
                    handle_rpc_message(
                        client_index,
                        &mut self.clients,
                        &mut self.state,
                        kind,
                        correlation,
                        ws_data,
                        payload,
                        &mut encoder,
                    );
                }

                let Some(client) = self.clients.get_mut(client_index as usize) else {
                    kvlog::error!("Write for missing client", index = client_index as usize);
                    return;
                };

                let _ = client.socket.write_all(encoder.output());

                rpc_stream.state.compact(&mut rpc_stream.buffer, 4096);

                if let Some(reason) = rpc_stream.termination_reason {
                    rpc_stream.buffer.clear();
                    self.buffer_pool.push(rpc_stream.buffer);
                    self.terminate_client(rpc_stream.client_index, reason);
                } else if rpc_stream.buffer.is_empty() {
                    self.buffer_pool.push(rpc_stream.buffer);
                } else {
                    client.partial_rpc_read = Some((rpc_stream.state, rpc_stream.buffer));
                }

                return;
            }
            ClientKind::Tui => handle_tui_client_read(&mut rpc_stream, client),
            ClientKind::Run { log_group } => handle_run_client_read(&mut rpc_stream, *log_group, &mut self.state),
            ClientKind::TestRun => handle_test_run_client_read(&mut rpc_stream),
            ClientKind::SelfLogs => handle_self_logs_client_read(&mut rpc_stream),
            ClientKind::Logs => handle_logs_client_read(&mut rpc_stream),
        }

        rpc_stream.state.compact(&mut rpc_stream.buffer, 4096);

        if let Some(reason) = rpc_stream.termination_reason {
            rpc_stream.buffer.clear();
            self.buffer_pool.push(rpc_stream.buffer);
            self.terminate_client(rpc_stream.client_index, reason);
        } else if rpc_stream.buffer.is_empty() {
            self.buffer_pool.push(rpc_stream.buffer);
        } else {
            client.partial_rpc_read = Some((rpc_stream.state, rpc_stream.buffer));
        }
    }

    pub(crate) fn handle_rpc_request(
        &mut self,
        mut socket: UnixStream,
        fds: ReceivedFds,
        kind: crate::rpc::RpcMessageKind,
        correlation: u16,
        one_shot: bool,
        ws_data: &[u8],
        payload: &[u8],
    ) {
        use crate::rpc::{self, CommandResponse, RpcMessageKind};

        let mut encoder = rpc::Encoder::new();
        match kind {
            RpcMessageKind::GetSelfLogs => {
                let Ok(req) = jsony::from_binary::<rpc::GetSelfLogsRequest>(payload) else {
                    kvlog::error!("Invalid GetSelfLogs request payload");
                    return;
                };

                if req.follow {
                    let ReceivedFds::Single(stdout) = fds else {
                        kvlog::error!("GetSelfLogs follow requires 1 FD");
                        return;
                    };
                    self.attach_self_logs_client(stdout, socket);
                    return;
                }

                let logs = crate::self_log::get_daemon_logs().unwrap_or_default();
                let _ = socket.write_all(&logs);
                return;
            }
            _ => {}
        }
        let Some(ws_index) = resolve_workspace_from_header(&mut self.state, ws_data, correlation, &mut encoder) else {
            let _ = socket.write_all(encoder.output());
            return;
        };
        let ws = &mut self.state.workspaces[ws_index as usize];

        let body = match kind {
            RpcMessageKind::SpawnTask => handle_rpc_restart_task(ws, payload),
            RpcMessageKind::KillTask => handle_rpc_kill_task(ws, payload),
            RpcMessageKind::RerunTests => handle_rpc_rerun_tests(ws, payload),
            RpcMessageKind::CallFunction => {
                let Ok(req) = jsony::from_binary::<rpc::CallFunctionRequest>(payload) else {
                    encoder.encode_response(
                        RpcMessageKind::CommandAck,
                        correlation,
                        &CommandResponse {
                            workspace_id: ws_index,
                            body: CommandBody::Error("Invalid request payload".into()),
                        },
                    );
                    let _ = socket.write_all(encoder.output());
                    return;
                };
                let ws = &self.state.workspaces[ws_index as usize];

                let body = match ws.handle.call_function(req.function_name) {
                    Ok(None) => CommandBody::Message("ok".into()),
                    Ok(Some(FunctionGlobalAction::RestartSelected)) => {
                        match restart_selected_from_clients(&self.clients, ws) {
                            Ok(()) => CommandBody::Empty,
                            Err(e) => CommandBody::Error(e.into()),
                        }
                    }
                    Err(e) => CommandBody::Error(e.into()),
                };
                body
            }
            RpcMessageKind::RestartSelected => {
                let ws = &self.state.workspaces[ws_index as usize];

                let body = match restart_selected_from_clients(&self.clients, ws) {
                    Ok(()) => CommandBody::Empty,
                    Err(e) => CommandBody::Error(e.into()),
                };
                body
            }
            RpcMessageKind::GetLoggedRustPanics => handle_rpc_get_logged_rust_panics(ws, payload),
            RpcMessageKind::AttachTui => {
                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    kvlog::error!("TUI client requires 2 FDs");
                    return;
                };

                self.attach_tui_client(stdin, stdout, socket, ws_index);
                return;
            }
            RpcMessageKind::AttachRun => {
                let Ok(req) = jsony::from_binary::<rpc::AttachRunRequest>(payload) else {
                    kvlog::error!("Invalid AttachRun request payload");
                    return;
                };

                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    kvlog::error!("Run client requires 2 FDs");
                    return;
                };

                self.attach_run_client(
                    stdin,
                    stdout,
                    socket,
                    ws_index,
                    req.task_name,
                    req.params.to_vec(),
                    req.as_test,
                );
                return;
            }
            RpcMessageKind::AttachTests => {
                let Ok(req) = jsony::from_binary::<rpc::AttachTestsRequest>(payload) else {
                    kvlog::error!("Invalid AttachTests request payload");
                    return;
                };

                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    kvlog::error!("Test client requires 2 FDs");
                    return;
                };

                self.attach_test_run_client(stdin, stdout, socket, ws_index, jsony::to_binary(&req.filters));
                return;
            }
            RpcMessageKind::AttachLogs => {
                let Ok(req) = jsony::from_binary::<rpc::AttachLogsRequest>(payload) else {
                    kvlog::error!("Invalid AttachLogs request payload");
                    return;
                };

                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    kvlog::error!("Logs client requires 2 FDs");
                    return;
                };

                self.attach_logs_client(stdin, stdout, socket, ws_index, jsony::to_binary(&req.query));
                return;
            }
            _ => {
                kvlog::warn!("Unhandled RPC message kind in handle_rpc_request", ?kind);
                CommandBody::Error("Unsupported command".into())
            }
        };

        encoder.encode_response(
            RpcMessageKind::CommandAck,
            correlation,
            &CommandResponse { workspace_id: ws_index, body },
        );
        let _ = socket.write_all(encoder.output());

        if !one_shot {
            self.register_client(
                socket,
                ws_index,
                ClientKind::Rpc { subscriptions: RpcSubscriptions::default() },
                None,
            );
        }
    }
}
