use super::*;
use crate::config::Command as ConfigCommand;
use crate::config::Requirement;
use crate::rpc::DecodeResult;
use crate::rpc::DecodingState;
use crate::workspace::{
    BaseTaskIndex, FunctionGlobalAction, Job, JobIndex, ScheduleRequirement, SpawnSpec, WorkspaceState as WsState,
};
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
        match self.state.decode(&self.buffer) {
            DecodeResult::Message { kind, correlation, one_shot, payload, ws_data } => {
                Some(ClientMessage { correlation, kind, one_shot, ws_data, payload })
            }
            DecodeResult::MissingData { .. } => None,
            DecodeResult::Empty => None,
            DecodeResult::Error(e) => {
                kvlog::error!("Test run client protocol decode error", ?e, index = self.client_index);
                self.termination_reason = Some(SocketTerminationReason::ProtocolError);
                None
            }
        }
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
                ReadResult::Eof => {
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
                SELECTED_META_GROUP_SERVICES => TaskKind::Service,
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
            let name = ws_state.spawn_name_for(bti);
            let params = job.spawn_params().clone();
            let profile = job.spawn_profile().to_string();
            drop(ws_state);
            if let Err(err) = ws.handle.submit(SpawnSpec::task(&name, &profile, params, true)) {
                kvlog::warn!("RPC meta-group restart failed", name, profile, err);
            }
        } else {
            let bti = workspace::BaseTaskIndex(selected as u32);
            let ws_state = ws.handle.state();
            if ws_state.base_tasks.get(bti.idx()).is_none() {
                return Err("selected task no longer exists");
            }
            let name = ws_state.spawn_name_for(bti);
            if let Some(&last_ji) = ws_state.base_tasks[bti.idx()].jobs.all().last() {
                let job = &ws_state[last_ji];
                let params = job.spawn_params().clone();
                let profile = job.spawn_profile().to_string();
                drop(ws_state);
                if let Err(err) = ws.handle.submit(SpawnSpec::task(&name, &profile, params, true)) {
                    kvlog::warn!("RPC task restart failed", name, profile, err);
                }
            } else {
                drop(ws_state);
                if let Err(err) = ws.handle.submit(SpawnSpec::task(&name, "", ValueMap::new(), true)) {
                    kvlog::warn!("RPC task fresh-start failed", name, err);
                }
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

fn handle_run_client_read(rpc_reader: &mut RpcClientStream, log_groups: &[LogGroup], state: &mut State) {
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
        for (_, process) in &mut state.processes {
            if log_groups.contains(&process.log_group) {
                process.request_termination(ExitCause::Killed);
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

fn resolve_workspace_from_header_result(
    state: &mut State,
    ws_data: &[u8],
) -> Result<WorkspaceIndex, rpc::HandlerError> {
    use crate::rpc::WorkspaceRef;

    if ws_data.is_empty() {
        return Err(rpc::HandlerError::new(1, "Workspace required"));
    }

    let ws_ref =
        jsony::from_binary::<WorkspaceRef>(ws_data).map_err(|_| rpc::HandlerError::new(2, "Invalid workspace ref"))?;

    resolve_workspace(state, &ws_ref).map_err(|e| rpc::HandlerError::new(3, e))
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
    token: rpc::ResponseToken<'_, '_>,
    client_index: ClientIndex,
    clients: &mut Slab<ClientEntry>,
    state: &mut State,
    kind: RpcMessageKind,
    ws_data: &[u8],
    payload: &[u8],
) -> Result<rpc::ResponseSent, rpc::HandlerError> {
    match kind {
        RpcMessageKind::Subscribe => {
            let filter = jsony::from_binary::<crate::rpc::SubscriptionFilter>(payload)
                .map_err(|_| rpc::HandlerError::new(1, "Invalid subscription filter"))?;
            let ClientKind::Rpc { subscriptions } = &mut clients[client_index as usize].kind else {
                return Err(rpc::HandlerError::new(2, "Not an RPC client"));
            };
            subscriptions.job_status = filter.job_status;
            subscriptions.job_exits = filter.job_exits;
            return Ok(token.respond(RpcMessageKind::SubscribeAck, &crate::rpc::SubscribeAck { success: true }));
        }
        RpcMessageKind::RunTask => {
            let ws_index = resolve_workspace_from_header_result(state, ws_data)?;
            let req = jsony::from_binary::<crate::rpc::RunTaskRequest>(payload)
                .map_err(|_| rpc::HandlerError::new(2, "Invalid run task request"))?;
            let params = jsony::from_binary::<ValueMap>(req.params).unwrap_or_else(|_| ValueMap::new()).to_owned();
            let ws = &state.workspaces[ws_index as usize];

            match ws.handle.submit(SpawnSpec::task(req.task_name, req.profile, params, true)) {
                Ok(result) => {
                    let ws_state = ws.handle.state();
                    let job_index = result.jobs.first().and_then(|(_, ji)| ws_state.jobs.public_id_of(*ji));
                    return Ok(token.respond(
                        RpcMessageKind::RunTaskAck,
                        &crate::rpc::RunTaskResponse { success: true, job_index, error: None },
                    ));
                }
                Err(e) => {
                    return Ok(token.respond(
                        RpcMessageKind::RunTaskAck,
                        &crate::rpc::RunTaskResponse { success: false, job_index: None, error: Some(e.into()) },
                    ));
                }
            }
        }
        RpcMessageKind::Terminate => {
            return Ok(token.respond_empty(RpcMessageKind::TerminateAck));
        }
        RpcMessageKind::OpenWorkspace => {
            return Ok(token.respond(
                RpcMessageKind::OpenWorkspaceAck,
                &crate::rpc::OpenWorkspaceResponse { success: true, error: None },
            ));
        }
        _ => {}
    }

    let ws_index = resolve_workspace_from_header_result(state, ws_data)?;
    let ws = &mut state.workspaces[ws_index as usize];
    let body = match kind {
        RpcMessageKind::SpawnTask => handle_rpc_legacy_spawn_task(ws, payload),
        RpcMessageKind::StartTask => handle_rpc_start_task(ws, payload),
        RpcMessageKind::RestartTask => handle_rpc_restart_task(ws, payload),
        RpcMessageKind::KillTask => handle_rpc_kill_task(ws, payload),
        RpcMessageKind::RerunTests => handle_rpc_rerun_tests(ws, payload),
        RpcMessageKind::CallFunction => handle_rpc_call_function(clients, ws, payload),
        RpcMessageKind::GetLoggedRustPanics => handle_rpc_get_logged_rust_panics(ws, payload),
        RpcMessageKind::GetStatus => handle_rpc_get_status(ws, payload),
        _ => {
            kvlog::warn!("Unexpected RPC message kind from client", ?kind);
            return Err(rpc::HandlerError::new(404, "Unknown message kind"));
        }
    };
    Ok(token.respond(RpcMessageKind::CommandAck, &crate::rpc::CommandResponse { workspace_id: ws_index, body }))
}

fn decode_spawn_request(payload: &[u8]) -> Result<(rpc::SpawnTaskRequest<'_>, ValueMap<'static>), CommandBody> {
    let Ok(req) = jsony::from_binary::<rpc::SpawnTaskRequest>(payload) else {
        return Err(CommandBody::Error("Invalid request payload".into()));
    };
    let params = jsony::from_binary::<ValueMap>(req.params).unwrap_or_else(|_| ValueMap::new()).to_owned();
    Ok((req, params))
}

fn handle_rpc_start_task(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let (req, params) = match decode_spawn_request(payload) {
        Ok(decoded) => decoded,
        Err(body) => return body,
    };

    if req.as_test {
        let mut spec = SpawnSpec::task(req.task_name, req.profile, params, false);
        spec.test_group = true;
        match ws.handle.submit_start(spec) {
            Ok(_) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        }
    } else {
        match ws.handle.start_task_by_name_cached(req.task_name, params, req.profile, req.cached) {
            Ok(None) => CommandBody::Empty,
            Ok(Some(msg)) => CommandBody::Message(msg.into()),
            Err(e) => CommandBody::Error(e.into()),
        }
    }
}

fn handle_rpc_restart_task(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let (req, params) = match decode_spawn_request(payload) {
        Ok(decoded) => decoded,
        Err(body) => return body,
    };

    if req.as_test {
        let mut spec = SpawnSpec::task(req.task_name, req.profile, params, true);
        spec.test_group = true;
        match ws.handle.submit(spec) {
            Ok(_) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        }
    } else if req.cached {
        match ws.handle.spawn_task_by_name_cached(req.task_name, params, req.profile, true, true) {
            Ok(None) => CommandBody::Empty,
            Ok(Some(msg)) => CommandBody::Message(msg.into()),
            Err(e) => CommandBody::Error(e.into()),
        }
    } else {
        match ws.handle.submit(SpawnSpec::task(req.task_name, req.profile, params, true)) {
            Ok(_) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        }
    }
}

fn handle_rpc_legacy_spawn_task(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let (req, params) = match decode_spawn_request(payload) {
        Ok(decoded) => decoded,
        Err(body) => return body,
    };

    if req.as_test {
        let mut spec = SpawnSpec::task(req.task_name, req.profile, params, false);
        spec.test_group = true;
        match ws.handle.submit(spec) {
            Ok(_) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        }
    } else if req.cached {
        match ws.handle.spawn_task_by_name_cached(req.task_name, params, req.profile, true, false) {
            Ok(None) => CommandBody::Empty,
            Ok(Some(msg)) => CommandBody::Message(msg.into()),
            Err(e) => CommandBody::Error(e.into()),
        }
    } else {
        match ws.handle.submit(SpawnSpec::task(req.task_name, req.profile, params, false)) {
            Ok(_) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        }
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

fn exit_cause_label(cause: ExitCause) -> &'static str {
    match cause {
        ExitCause::Unknown => "unknown",
        ExitCause::Killed => "killed",
        ExitCause::Restarted => "restarted",
        ExitCause::SpawnFailed => "spawn_failed",
        ExitCause::ProfileConflict => "profile_conflict",
        ExitCause::Timeout => "timeout",
    }
}

fn job_state_label(job: &Job) -> &'static str {
    match &job.process_status {
        JobStatus::Scheduled { .. } => "scheduled",
        JobStatus::Starting => "starting",
        JobStatus::Running { ready_state: Some(false), .. } => "running (not ready)",
        JobStatus::Running { .. } => "running",
        JobStatus::Exited { status: 0, cause: ExitCause::Restarted, .. } => "restarted",
        JobStatus::Exited { status, .. } => {
            if *status == 0 {
                "exited (success)"
            } else {
                "exited (failure)"
            }
        }
        JobStatus::Cancelled => "cancelled",
    }
}

fn job_ready_state(job: &Job) -> Option<bool> {
    match &job.process_status {
        JobStatus::Running { ready_state, .. } => *ready_state,
        _ => None,
    }
}

fn job_exit_info(job: &Job) -> (Option<i32>, Option<Box<str>>) {
    match &job.process_status {
        JobStatus::Exited { status, cause: ExitCause::Unknown, .. } => (Some(*status as i32), None),
        JobStatus::Exited { status, cause, .. } => (Some(*status as i32), Some(exit_cause_label(*cause).into())),
        JobStatus::Cancelled => (None, Some("cancelled".into())),
        _ => (None, None),
    }
}

fn job_duration_ms(job: &Job) -> Option<u64> {
    let started = job.started_at;
    let end = match &job.process_status {
        JobStatus::Exited { finished_at, .. } => *finished_at,
        JobStatus::Running { .. } | JobStatus::Starting | JobStatus::Scheduled { .. } => crate::clock::now(),
        JobStatus::Cancelled => return None,
    };
    end.checked_duration_since(started).map(|d| d.as_millis() as u64)
}

fn job_age_secs(job: &Job) -> Option<u64> {
    crate::clock::now().checked_duration_since(job.started_at).map(|d| d.as_secs())
}

fn render_command(cmd: &ConfigCommand<'_>) -> Box<str> {
    match cmd {
        ConfigCommand::Sh { script, args } => {
            let mut rendered = format!("sh -c {script:?}");
            let parts = if args.is_empty() { &[][..] } else { &["devsm"][..] };
            for arg in parts.iter().copied().chain(args.iter().copied()) {
                rendered.push(' ');
                if arg.contains(' ') || arg.is_empty() {
                    rendered.push_str(&format!("{arg:?}"));
                } else {
                    rendered.push_str(arg);
                }
            }
            rendered.into()
        }
        ConfigCommand::Cmd(parts) => {
            let mut out = String::new();
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                if p.contains(' ') || p.is_empty() {
                    out.push_str(&format!("{p:?}"));
                } else {
                    out.push_str(p);
                }
            }
            out.into()
        }
    }
}

fn blockers_for_scheduled(state: &WsState, after: &[ScheduleRequirement]) -> Vec<Box<str>> {
    let mut out = Vec::new();
    for req in after {
        match req {
            ScheduleRequirement::Task { job: ji, predicate } => {
                let Some(blocking_job) = state.jobs.get(*ji) else {
                    continue;
                };
                let bti = blocking_job.log_group.base_task_index();
                let name = state.base_tasks.get(bti.idx()).map(|bt| bt.name.as_ref()).unwrap_or("?");
                let kind = state.base_tasks.get(bti.idx()).map(|bt| bt.config.kind.as_str()).unwrap_or("task");
                out.push(format!("{kind}.{name} ({:?})", predicate).into());
            }
            ScheduleRequirement::Resource { id, .. } => {
                if !state.resources.is_free(*id) {
                    out.push(format!("resource {}", state.resources.name(*id)).into());
                }
            }
        }
    }
    out
}

fn last_job_for_base_task(state: &WsState, bti: BaseTaskIndex) -> Option<JobIndex> {
    let bt = state.base_tasks.get(bti.idx())?;
    let non_term = bt.jobs.non_terminal();
    if let Some(&ji) = non_term.last() {
        return Some(ji);
    }
    bt.jobs.terminal().last().copied()
}

fn base_runnable_status(state: &WsState, bti: BaseTaskIndex) -> rpc::RunnableStatus {
    let bt = &state.base_tasks[bti.idx()];
    rpc::RunnableStatus {
        name: bt.name.clone(),
        kind: bt.config.kind.as_str().into(),
        state: "never run".into(),
        last_job_id: None,
        last_run_started_secs_ago: None,
        last_run_duration_ms: None,
        exit_code: None,
        exit_cause: None,
        ready: None,
        blocked_on: Vec::new(),
        profile: None,
        spawn_params: None,
        config_generation_id: None,
        config_is_current: true,
        pwd: None,
        command: None,
        envvars: Vec::new(),
        require: Vec::new(),
    }
}

fn add_job_to_runnable_status(
    state: &WsState,
    status: &mut rpc::RunnableStatus,
    ji: JobIndex,
    job: &Job,
    detailed: bool,
) {
    status.state = job_state_label(job).into();
    status.last_job_id = state.jobs.public_id_of(ji);
    status.last_run_started_secs_ago = job_age_secs(job);
    status.last_run_duration_ms = job_duration_ms(job);
    let (code, cause) = job_exit_info(job);
    status.exit_code = code;
    status.exit_cause = cause;
    status.ready = job_ready_state(job);

    let profile = job.spawn_profile();
    if !profile.is_empty() {
        status.profile = Some(profile.into());
    }
    let params = job.spawn_params();
    if !params.entries().is_empty() {
        status.spawn_params = Some(jsony::to_json(params).into());
    }

    status.config_generation_id = Some(job.spawn.generation_id);
    status.config_is_current = job.spawn.generation_id == state.config.current.id();

    if let JobStatus::Scheduled { after } = &job.process_status {
        status.blocked_on = blockers_for_scheduled(state, after);
    }

    if detailed {
        let tc = job.task().config();
        status.pwd = Some(tc.pwd.into());
        status.command = Some(render_command(&tc.command));
        status.envvars = tc.envvar.iter().map(|(k, v)| format!("{k}={v}").into()).collect();
        status.require = render_requirements(tc.require);
    }
}

fn render_requirement(requirement: &Requirement<'_>) -> Box<str> {
    match requirement {
        Requirement::Task(call) => {
            let p = call.profile.unwrap_or("");
            if p.is_empty() {
                format!("task {}", &*call.name).into()
            } else {
                format!("task {}:{}", &*call.name, p).into()
            }
        }
        Requirement::Resource { name, priority } => format!("resource {name} (priority {priority})").into(),
    }
}

fn render_requirements(requirements: &[Requirement<'_>]) -> Vec<Box<str>> {
    requirements.iter().map(render_requirement).collect()
}

fn add_unevaluated_runnable_requirements(state: &WsState, bti: BaseTaskIndex, status: &mut rpc::RunnableStatus) {
    let expr = state.base_tasks[bti.idx()].config.expr();
    let mut require = Vec::new();
    for item in expr.require {
        item.visit_requirements(&mut |r| require.push(render_requirement(r)));
    }
    status.require = require;
}

fn build_runnable_status_for_job(
    state: &WsState,
    bti: BaseTaskIndex,
    ji: JobIndex,
    detailed: bool,
) -> rpc::RunnableStatus {
    let mut status = base_runnable_status(state, bti);
    let job = &state.jobs[ji];
    add_job_to_runnable_status(state, &mut status, ji, job, detailed);
    status
}

fn build_runnable_status(state: &WsState, bti: BaseTaskIndex, detailed: bool) -> rpc::RunnableStatus {
    let mut status = base_runnable_status(state, bti);
    if let Some(ji) = last_job_for_base_task(state, bti) {
        let job = &state.jobs[ji];
        add_job_to_runnable_status(state, &mut status, ji, job, detailed);
    } else if detailed {
        add_unevaluated_runnable_requirements(state, bti, &mut status);
    }
    status
}

fn group_overall(runnables: &[rpc::RunnableStatus]) -> Box<str> {
    if runnables.is_empty() {
        return "empty".into();
    }
    let mut any_running = false;
    let mut any_scheduled = false;
    let mut any_failed = false;
    let mut all_success = true;
    let mut any_run = false;
    for r in runnables {
        let s = r.state.as_ref();
        if s.starts_with("running") || s == "starting" {
            any_running = true;
            any_run = true;
        } else if s == "scheduled" {
            any_scheduled = true;
            any_run = true;
        } else if s == "exited (failure)" || s == "cancelled" {
            any_failed = true;
            all_success = false;
            any_run = true;
        } else if s == "exited (success)" || s == "restarted" {
            any_run = true;
        } else if s == "never run" {
            all_success = false;
        }
    }
    if !any_run {
        return "never run".into();
    }
    if any_running {
        return "active".into();
    }
    if any_scheduled {
        return "scheduled".into();
    }
    if any_failed {
        return "degraded".into();
    }
    if all_success {
        return "ok".into();
    }
    "mixed".into()
}

fn handle_rpc_get_status(ws: &mut WorkspaceEntry, payload: &[u8]) -> CommandBody {
    let Ok(req) = jsony::from_binary::<rpc::GetStatusRequest>(payload) else {
        return CommandBody::Error("Invalid request payload".into());
    };

    ws.handle.refresh_config_if_changed();
    let state = ws.handle.state();
    let name = req.name;

    if name.is_empty() {
        let mut runnables: Vec<_> = state
            .jobs
            .iter()
            .filter(|(_, job)| job.process_status.is_pending_completion())
            .map(|(ji, job)| build_runnable_status_for_job(&state, job.spawn.base_task, ji, false))
            .collect();
        runnables.sort_by_key(|r| r.last_job_id.unwrap_or(u32::MAX));
        let resp = rpc::StatusResponse::Global(rpc::GlobalStatus { runnables });
        return CommandBody::Message(jsony::to_json(&resp).into());
    }

    let explicit_group = WsState::is_explicit_group_reference(name);

    if !explicit_group {
        if let Some(bti) = state.lookup_name(name) {
            let status = build_runnable_status(&state, bti, true);
            let resp = rpc::StatusResponse::Task(status);
            return CommandBody::Message(jsony::to_json(&resp).into());
        }
    }

    let short = match name.split_once('.') {
        Some(("group", rest)) => rest,
        Some(("service" | "action" | "test", _)) => {
            return CommandBody::Error(format!("Task '{}' not found", name).into());
        }
        _ => name,
    };
    let Some((group_name, calls)) = state.config.current.workspace().groups.iter().find(|(g, _)| *g == short) else {
        if explicit_group {
            return CommandBody::Error(format!("Group '{}' not found", short).into());
        }
        return CommandBody::Error(format!("'{}' is not a known task or group", name).into());
    };

    let mut runnables = Vec::with_capacity(calls.len());
    for call in *calls {
        let call_name: &str = &call.name;
        let Some(bti) = state.lookup_name(call_name) else {
            runnables.push(rpc::RunnableStatus {
                name: call_name.into(),
                kind: "?".into(),
                state: "not configured".into(),
                last_job_id: None,
                last_run_started_secs_ago: None,
                last_run_duration_ms: None,
                exit_code: None,
                exit_cause: None,
                ready: None,
                blocked_on: Vec::new(),
                profile: None,
                spawn_params: None,
                config_generation_id: None,
                config_is_current: true,
                pwd: None,
                command: None,
                envvars: Vec::new(),
                require: Vec::new(),
            });
            continue;
        };
        runnables.push(build_runnable_status(&state, bti, false));
    }

    let overall = group_overall(&runnables);
    let resp = rpc::StatusResponse::Group(rpc::GroupStatus { name: (*group_name).into(), overall, runnables });
    CommandBody::Message(jsony::to_json(&resp).into())
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
        kvlog::error!("Unexpected message kind from test client", kind = ?message.kind)
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
                    let mut response = rpc::ResponseState::new(&mut encoder, correlation);
                    let result = handle_rpc_message(
                        response.token(),
                        client_index,
                        &mut self.clients,
                        &mut self.state,
                        kind,
                        ws_data,
                        payload,
                    );
                    response.finish(result);
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
            ClientKind::Run { log_groups } => handle_run_client_read(&mut rpc_stream, log_groups, &mut self.state),
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
        socket: UnixStream,
        fds: ReceivedFds,
        kind: crate::rpc::RpcMessageKind,
        correlation: u16,
        one_shot: bool,
        ws_data: &[u8],
        payload: &[u8],
        remaining: Vec<u8>,
    ) -> Result<RpcOutcome, RpcError> {
        // Handle GetSelfLogs specially (global command, no workspace)
        if kind == RpcMessageKind::GetSelfLogs {
            return self.handle_get_self_logs(socket, fds, payload, correlation);
        }

        if kind == RpcMessageKind::GetWorkspaces {
            return self.handle_get_workspaces(socket, payload, correlation);
        }

        // Resolve workspace for all other commands
        let ws_index = match resolve_workspace_from_header_result(&mut self.state, ws_data) {
            Ok(idx) => idx,
            Err(e) => return Err(RpcError { socket, error: e, correlation }),
        };

        // Handle attach commands
        let socket = match self.try_handle_attach(socket, fds, kind, ws_index, payload, correlation)? {
            AttachOutcome::Attached => return Ok(RpcOutcome::Attached),
            AttachOutcome::NotAttach(socket) => socket,
        };

        // Handle regular RPC commands with ResponseToken pattern
        let mut encoder = rpc::Encoder::new();
        let mut response = rpc::ResponseState::new(&mut encoder, correlation);
        let result = handle_rpc_request_command(
            response.token(),
            &self.clients,
            &mut self.state.workspaces[ws_index as usize],
            ws_index,
            kind,
            payload,
        );
        response.finish(result);

        let register = if one_shot {
            None
        } else {
            let partial = if remaining.is_empty() { None } else { Some((DecodingState::default(), remaining)) };
            Some((ws_index, partial))
        };

        Ok(RpcOutcome::Respond { socket, encoder, register })
    }

    fn handle_get_self_logs(
        &mut self,
        socket: UnixStream,
        fds: ReceivedFds,
        payload: &[u8],
        correlation: u16,
    ) -> Result<RpcOutcome, RpcError> {
        let Ok(req) = jsony::from_binary::<rpc::GetSelfLogsRequest>(payload) else {
            return Err(RpcError::new(socket, 2, "Invalid GetSelfLogs payload", correlation));
        };

        if req.follow {
            let ReceivedFds::Single(stdout) = fds else {
                return Err(RpcError::new(socket, 1, "GetSelfLogs follow requires 1 FD", correlation));
            };
            self.attach_self_logs_client(stdout, socket);
            Ok(RpcOutcome::Attached)
        } else {
            let logs = crate::self_log::get_daemon_logs().unwrap_or_default();
            Ok(RpcOutcome::RawWrite { socket, data: logs })
        }
    }

    fn handle_get_workspaces(
        &mut self,
        socket: UnixStream,
        payload: &[u8],
        correlation: u16,
    ) -> Result<RpcOutcome, RpcError> {
        let Ok(_) = jsony::from_binary::<rpc::GetWorkspacesRequest>(payload) else {
            return Err(RpcError::new(socket, 2, "Invalid GetWorkspaces payload", correlation));
        };

        let db_workspaces = self.state.db.workspaces();
        let loaded_paths: hashbrown::HashSet<&Path> = self.state.workspace_map.keys().map(|p| p.as_ref()).collect();

        let infos: Vec<rpc::WorkspaceInfo> = db_workspaces
            .into_iter()
            .map(|w| {
                let currently_loaded = loaded_paths.contains(Path::new(w.config_path.as_str()));
                rpc::WorkspaceInfo {
                    config_path: w.config_path.into(),
                    last_loaded_ms: w.last_loaded.ms(),
                    currently_loaded,
                }
            })
            .collect();

        let body = CommandBody::Message(jsony::to_json(&rpc::GetWorkspacesResponse { workspaces: infos }).into());

        let mut encoder = rpc::Encoder::new();
        encoder.encode_response(
            RpcMessageKind::CommandAck,
            correlation,
            &rpc::CommandResponse { workspace_id: 0, body },
        );
        Ok(RpcOutcome::Respond { socket, encoder, register: None })
    }

    /// Try to handle attach commands. Returns the socket back if not an attach command.
    fn try_handle_attach(
        &mut self,
        socket: UnixStream,
        fds: ReceivedFds,
        kind: RpcMessageKind,
        ws_index: WorkspaceIndex,
        payload: &[u8],
        correlation: u16,
    ) -> Result<AttachOutcome, RpcError> {
        match kind {
            RpcMessageKind::AttachTui => {
                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    return Err(RpcError::new(socket, 1, "AttachTui requires 2 FDs", correlation));
                };
                self.attach_tui_client(stdin, stdout, socket, ws_index);
                Ok(AttachOutcome::Attached)
            }
            RpcMessageKind::AttachRun => {
                let Ok(req) = jsony::from_binary::<rpc::AttachRunRequest>(payload) else {
                    return Err(RpcError::new(socket, 2, "Invalid AttachRun payload", correlation));
                };
                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    return Err(RpcError::new(socket, 1, "AttachRun requires 2 FDs", correlation));
                };
                self.attach_run_client(
                    stdin,
                    stdout,
                    socket,
                    ws_index,
                    req.task_name,
                    req.params.to_vec(),
                    req.as_test,
                    req.derive_cache_key,
                );
                Ok(AttachOutcome::Attached)
            }
            RpcMessageKind::AttachTests => {
                let Ok(req) = jsony::from_binary::<rpc::AttachTestsRequest>(payload) else {
                    return Err(RpcError::new(socket, 2, "Invalid AttachTests payload", correlation));
                };
                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    return Err(RpcError::new(socket, 1, "AttachTests requires 2 FDs", correlation));
                };
                self.attach_test_run_client(stdin, stdout, socket, ws_index, jsony::to_binary(&req.filters));
                Ok(AttachOutcome::Attached)
            }
            RpcMessageKind::AttachLogs => {
                let Ok(req) = jsony::from_binary::<rpc::AttachLogsRequest>(payload) else {
                    return Err(RpcError::new(socket, 2, "Invalid AttachLogs payload", correlation));
                };
                let ReceivedFds::Pair([stdin, stdout]) = fds else {
                    return Err(RpcError::new(socket, 1, "AttachLogs requires 2 FDs", correlation));
                };
                self.attach_logs_client(stdin, stdout, socket, ws_index, jsony::to_binary(&req.query));
                Ok(AttachOutcome::Attached)
            }
            _ => Ok(AttachOutcome::NotAttach(socket)),
        }
    }
}

enum AttachOutcome {
    Attached,
    NotAttach(UnixStream),
}

/// Outcome of handling an RPC request.
pub(crate) enum RpcOutcome {
    /// Attach command consumed the socket.
    Attached,
    /// Raw data to write (for GetSelfLogs non-follow).
    RawWrite { socket: UnixStream, data: Vec<u8> },
    /// Encoded response ready to write.
    Respond {
        socket: UnixStream,
        encoder: rpc::Encoder,
        /// If Some, register as persistent client after writing response.
        register: Option<(WorkspaceIndex, Option<(DecodingState, Vec<u8>)>)>,
    },
}

/// Error from RPC request handling.
pub(crate) struct RpcError {
    pub socket: UnixStream,
    pub error: rpc::HandlerError,
    pub correlation: u16,
}

impl RpcError {
    fn new(socket: UnixStream, code: u32, message: &str, correlation: u16) -> Self {
        Self { socket, error: rpc::HandlerError::new(code, message), correlation }
    }
}

fn handle_rpc_request_command(
    token: rpc::ResponseToken<'_, '_>,
    clients: &Slab<ClientEntry>,
    ws: &mut WorkspaceEntry,
    ws_index: WorkspaceIndex,
    kind: RpcMessageKind,
    payload: &[u8],
) -> Result<rpc::ResponseSent, rpc::HandlerError> {
    let body = match kind {
        RpcMessageKind::SpawnTask => handle_rpc_legacy_spawn_task(ws, payload),
        RpcMessageKind::StartTask => handle_rpc_start_task(ws, payload),
        RpcMessageKind::RestartTask => handle_rpc_restart_task(ws, payload),
        RpcMessageKind::KillTask => handle_rpc_kill_task(ws, payload),
        RpcMessageKind::RerunTests => handle_rpc_rerun_tests(ws, payload),
        RpcMessageKind::CallFunction => handle_rpc_call_function(clients, ws, payload),
        RpcMessageKind::RestartSelected => match restart_selected_from_clients(clients, ws) {
            Ok(()) => CommandBody::Empty,
            Err(e) => CommandBody::Error(e.into()),
        },
        RpcMessageKind::GetLoggedRustPanics => handle_rpc_get_logged_rust_panics(ws, payload),
        RpcMessageKind::GetStatus => handle_rpc_get_status(ws, payload),
        _ => return Err(rpc::HandlerError::new(404, "Unknown command")),
    };
    Ok(token.respond(RpcMessageKind::CommandAck, &rpc::CommandResponse { workspace_id: ws_index, body }))
}
