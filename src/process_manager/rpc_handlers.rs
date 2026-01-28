use super::*;
use crate::rpc::DecodeResult;
use crate::rpc::DecodingState;
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
    fn finish(mut self, pm: &mut ProcessManager) {
        self.state.compact(&mut self.buffer, 4096);

        if let Some(reason) = self.termination_reason {
            self.buffer.clear();
            pm.buffer_pool.push(self.buffer);
            pm.terminate_client(self.client_index, reason);
        } else if self.buffer.is_empty() {
            pm.buffer_pool.push(self.buffer);
        } else {
            let Some(client) = pm.clients.get_mut(self.client_index as usize) else { return };
            client.partial_rpc_read = Some((self.state, self.buffer));
        }
    }
    fn read<'a>(&'a mut self, socket: &mut UnixStream) {
        loop {
            match try_read(socket.as_raw_fd(), &mut self.buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    self.termination_reason = Some(SocketTerminationReason::Eof);
                    break;
                }
                ReadResult::Done => break,
                ReadResult::WouldBlock => break,
                ReadResult::OtherError(err) => {
                    kvlog::error!("Test run client read failed", ?err, index = self.client_index);
                    self.termination_reason = Some(SocketTerminationReason::ReadError);
                    break;
                }
            }
        }
    }
    fn next<'a>(&'a mut self) -> Option<ClientMessage<'a>> {
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
        reader.read(&mut self.socket);
        reader
    }
}

impl ProcessManager {
    pub fn handle_test_run_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let mut rpc_reader = client.rpc_stream(&mut self.buffer_pool, client_index);
        while let Some(message) = rpc_reader.next() {
            match message.kind {
                RpcMessageKind::Terminate => rpc_reader.client_requests_termination(),
                _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
            }
        }
        rpc_reader.finish(self);
    }

    pub(crate) fn handle_rpc_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let mut rpc_reader = client.rpc_stream(&mut self.buffer_pool, client_index);
        let mut encoder = crate::rpc::Encoder::new();
        while let Some(ClientMessage { kind, correlation, ws_data, payload, .. }) = rpc_reader.next() {
            self.handle_rpc_message(client_index, kind, correlation, ws_data, payload, &mut encoder);
        }

        if let Some(client) = self.clients.get_mut(client_index as usize) {
            let _ = client.socket.write_all(encoder.output());
        } else {
            kvlog::warn!("Client disconnected before sending RPC response", index = client_index);
        }

        rpc_reader.finish(self);
    }

    pub fn handle_client_rpc_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get(client_index as usize) else {
            kvlog::error!("Read for missing client", index = client_index as usize);
            return;
        };

        // once we refactor the event loop to split up the components we'll be able to simply this even more
        match &client.kind {
            ClientKind::Tui => self.handle_tui_client_read(client_index),
            ClientKind::Run { log_group } => self.handle_run_client_read(client_index, *log_group),
            ClientKind::TestRun => self.handle_test_run_client_read(client_index),
            ClientKind::Rpc { .. } => self.handle_rpc_client_read(client_index),
            ClientKind::SelfLogs => self.handle_self_logs_client_read(client_index),
            ClientKind::Logs => self.handle_logs_client_read(client_index),
        }
    }
    fn handle_tui_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let mut rpc_reader = client.rpc_stream(&mut self.buffer_pool, client_index);
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
        rpc_reader.finish(self);
    }

    fn handle_run_client_read(&mut self, client_index: ClientIndex, job_id: LogGroup) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let mut rpc_reader = client.rpc_stream(&mut self.buffer_pool, client_index);
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
            for (_, process) in &self.processes {
                if process.log_group == job_id {
                    let child_pid = process.child.id();
                    let pgid = -(child_pid as i32);
                    unsafe {
                        libc::kill(pgid, libc::SIGINT);
                    }
                    break;
                }
            }
        }

        rpc_reader.finish(self);
    }

    fn handle_logs_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let mut rpc_reader = client.rpc_stream(&mut self.buffer_pool, client_index);
        while let Some(message) = rpc_reader.next() {
            match message.kind {
                RpcMessageKind::Terminate => {
                    rpc_reader.client_requests_termination();
                }
                _ => kvlog::error!("Unexpected message kind from test client", kind = ?message.kind),
            }
        }

        rpc_reader.finish(self);
    }

    pub(crate) fn handle_rpc_message(
        &mut self,
        client_index: ClientIndex,
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
                let Some(client) = self.clients.get_mut(client_index as usize) else { return };
                let ClientKind::Rpc { subscriptions } = &mut client.kind else { return };
                subscriptions.job_status = filter.job_status;
                subscriptions.job_exits = filter.job_exits;
                encoder.encode_response(
                    RpcMessageKind::SubscribeAck,
                    correlation,
                    &crate::rpc::SubscribeAck { success: true },
                );
            }
            RpcMessageKind::RunTask => {
                let Some(ws_index) = self.resolve_workspace_from_header(ws_data, correlation, encoder) else {
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
                let ws = &self.workspaces[ws_index as usize];
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
            RpcMessageKind::SpawnTask
            | RpcMessageKind::KillTask
            | RpcMessageKind::RerunTests
            | RpcMessageKind::CallFunction
            | RpcMessageKind::GetLoggedRustPanics => {
                let Some(ws_index) = self.resolve_workspace_from_header(ws_data, correlation, encoder) else {
                    return;
                };
                let body = match kind {
                    RpcMessageKind::SpawnTask => self.handle_rpc_restart_task(ws_index, payload),
                    RpcMessageKind::KillTask => self.handle_rpc_kill_task(ws_index, payload),
                    RpcMessageKind::RerunTests => self.handle_rpc_rerun_tests(ws_index, payload),
                    RpcMessageKind::CallFunction => self.handle_rpc_call_function(ws_index, payload),
                    RpcMessageKind::GetLoggedRustPanics => self.handle_rpc_get_logged_rust_panics(ws_index, payload),
                    _ => unreachable!(),
                };
                encoder.encode_response(
                    RpcMessageKind::CommandAck,
                    correlation,
                    &crate::rpc::CommandResponse { workspace_id: ws_index, body },
                );
            }
            _ => {
                kvlog::warn!("Unexpected RPC message kind from client", ?kind);
            }
        }
    }

    fn resolve_workspace(&mut self, ws_ref: &crate::rpc::WorkspaceRef) -> Result<WorkspaceIndex, String> {
        match ws_ref {
            crate::rpc::WorkspaceRef::Id(id) => {
                if (*id as usize) < self.workspaces.len() {
                    Ok(*id)
                } else {
                    Err(format!("Invalid workspace ID: {}", id))
                }
            }
            crate::rpc::WorkspaceRef::Path { config } => {
                self.workspace_index(config.to_path_buf()).map_err(|e| e.to_string())
            }
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
        let Some(ws_index) = self.resolve_workspace_from_header(ws_data, correlation, &mut encoder) else {
            let _ = socket.write_all(encoder.output());
            return;
        };

        let body = match kind {
            RpcMessageKind::SpawnTask => self.handle_rpc_restart_task(ws_index, payload),
            RpcMessageKind::KillTask => self.handle_rpc_kill_task(ws_index, payload),
            RpcMessageKind::RerunTests => self.handle_rpc_rerun_tests(ws_index, payload),
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
                let ws = &self.workspaces[ws_index as usize];

                let body = match ws.handle.call_function(req.function_name) {
                    Ok(msg) => CommandBody::Message(msg.into()),
                    Err(e) if e == "RestartSelected" => match self.restart_selected_from_clients(ws_index, ws) {
                        Ok(()) => CommandBody::Empty,
                        Err(e) => CommandBody::Error(e.into()),
                    },
                    Err(e) => CommandBody::Error(e.into()),
                };
                body
            }
            RpcMessageKind::RestartSelected => {
                let ws = &self.workspaces[ws_index as usize];

                let body = match self.restart_selected_from_clients(ws_index, ws) {
                    Ok(()) => CommandBody::Empty,
                    Err(e) => CommandBody::Error(e.into()),
                };
                body
            }
            RpcMessageKind::GetLoggedRustPanics => self.handle_rpc_get_logged_rust_panics(ws_index, payload),
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
    fn resolve_workspace_from_header(
        &mut self,
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

        match self.resolve_workspace(&ws_ref) {
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

    fn handle_rpc_restart_task(&mut self, ws_index: WorkspaceIndex, payload: &[u8]) -> CommandBody {
        let Ok(req) = jsony::from_binary::<rpc::SpawnTaskRequest>(payload) else {
            return CommandBody::Error("Invalid request payload".into());
        };

        let ws = &self.workspaces[ws_index as usize];
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

    fn handle_rpc_kill_task(&mut self, ws_index: WorkspaceIndex, payload: &[u8]) -> CommandBody {
        let Ok(req) = jsony::from_binary::<rpc::KillTaskRequest>(payload) else {
            return CommandBody::Error("Invalid request payload".into());
        };

        let ws = &self.workspaces[ws_index as usize];
        match ws.handle.terminate_task_by_name(req.task_name) {
            Ok(msg) => CommandBody::Message(msg.into()),
            Err(e) => CommandBody::Error(e.into()),
        }
    }

    fn handle_rpc_rerun_tests(&mut self, ws_index: WorkspaceIndex, payload: &[u8]) -> CommandBody {
        let Ok(req) = jsony::from_binary::<rpc::RerunTestsRequest>(payload) else {
            return CommandBody::Error("Invalid request payload".into());
        };

        let ws = &self.workspaces[ws_index as usize];
        match ws.handle.rerun_test_group(req.only_failed) {
            Ok(_) => CommandBody::Message("Rerunning tests".into()),
            Err(e) => CommandBody::Error(e.to_string().into()),
        }
    }

    fn handle_rpc_call_function(&mut self, ws_index: WorkspaceIndex, payload: &[u8]) -> CommandBody {
        let Ok(req) = jsony::from_binary::<rpc::CallFunctionRequest>(payload) else {
            return CommandBody::Error("Invalid request payload".into());
        };

        let ws = &self.workspaces[ws_index as usize];
        match ws.handle.call_function(req.function_name) {
            Ok(msg) => CommandBody::Message(msg.into()),
            Err(e) => CommandBody::Error(e.into()),
        }
    }

    fn handle_rpc_get_logged_rust_panics(&mut self, ws_index: WorkspaceIndex, payload: &[u8]) -> CommandBody {
        let Ok(_) = jsony::from_binary::<rpc::GetLoggedRustPanicsRequest>(payload) else {
            return CommandBody::Error("Invalid request payload".into());
        };

        let response = jsony::to_json(&self.workspaces[ws_index as usize].handle.logged_rust_panics());
        CommandBody::Message(response.into())
    }
}
