# Fish shell completions for devsm
# Source: completions/fish/devsm.fish
# Install: cp completions/fish/devsm.fish ~/.config/fish/completions/

# Helper: check if we need a subcommand
function __fish_devsm_needs_command
    set -l cmd (commandline -xpc)
    set -l count (count $cmd)

    if test $count -eq 1
        return 0
    end

    # Check if we have a subcommand (not a flag)
    for i in (seq 2 $count)
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            return 1
        end
    end
    return 0
end

# Helper: check if using a specific subcommand
function __fish_devsm_using_command
    set -l cmd (commandline -xpc)
    set -l target $argv[1]

    for arg in $cmd[2..]
        if not string match -q -- '-*' $arg
            if test "$arg" = "$target"
                return 0
            end
            return 1
        end
    end
    return 1
end

function __fish_devsm_is_explicit_task_command
    switch $argv[1]
        case run exec start restart stop
            return 0
    end
    return 1
end

function __fish_devsm_is_builtin_command
    switch $argv[1]
        case global run exec start restart restart-selected stop test rerun-tests logs get function self
            return 0
    end
    return 1
end

function __fish_devsm_first_nonflag
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            printf '%s\n%s\n' $arg $i
            return 0
        end
    end
    return 1
end

function __fish_devsm_using_implicit_task
    set -l first (__fish_devsm_first_nonflag)
    if test (count $first) -eq 0
        return 1
    end

    set -l command $first[1]
    if __fish_devsm_is_builtin_command $command
        return 1
    end
    return 0
end

# Helper: check if we need a task name (no task entered yet, not completing profile)
function __fish_devsm_needs_task
    # If current token contains ':', we're completing a profile, not a task
    set -l token (commandline -ct)
    if string match -q -- '*:*' $token
        return 1
    end

    set -l cmd (commandline -xpc)
    set -l found_subcommand 0

    for arg in $cmd[2..]
        if not string match -q -- '-*' $arg
            if test $found_subcommand -eq 0
                set found_subcommand 1
            else
                # Found something after the subcommand - task already entered
                return 1
            end
        end
    end
    return 0
end

# Helper: check if current token is completing a profile (ends with :)
function __fish_devsm_completing_profile
    set -l token (commandline -ct)
    string match -q -- '*:*' $token
end

# Helper: get task from current token (for profile completion)
function __fish_devsm_task_from_token
    set -l token (commandline -ct)
    echo $token | string replace -r ':.*' ''
end

# Helper: get current task from a tokenized commandline (for var completion)
function __fish_devsm_current_task_from_tokens
    set -l cmd $argv
    set -l command
    set -l command_index

    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            set command $arg
            set command_index $i
            break
        end
    end

    if test -z "$command"
        return 1
    end

    if not __fish_devsm_is_builtin_command $command
        echo $command | string replace -r ':.*' ''
        return 0
    end

    if not __fish_devsm_is_explicit_task_command $command
        return 1
    end

    for i in (seq (math $command_index + 1) (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            # Extract task name (strip :profile if present)
            echo $arg | string replace -r ':.*' ''
            return 0
        end
    end
    return 1
end

# Helper: get current task from commandline (for var completion)
function __fish_devsm_current_task
    __fish_devsm_current_task_from_tokens (commandline -xpc)
end

# Helper: check if the current commandline already has a task argument.
function __fish_devsm_has_task
    set -l cmd (commandline -xpc)
    set -l command
    set -l command_index

    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            set command $arg
            set command_index $i
            break
        end
    end

    if test -z "$command"
        return 1
    end

    if not __fish_devsm_is_builtin_command $command
        return 0
    end

    if not __fish_devsm_is_explicit_task_command $command
        return 1
    end

    for i in (seq (math $command_index + 1) (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            return 0
        end
    end

    return 1
end

# Helper: get tasks from config
function __fish_devsm_tasks
    devsm self complete tasks 2>/dev/null
end

# Helper: get tests from config
function __fish_devsm_tests
    devsm self complete tests 2>/dev/null
end

# Helper: get groups from config
function __fish_devsm_groups
    devsm self complete groups 2>/dev/null
end

function __fish_devsm_runnables
    __fish_devsm_tasks
    __fish_devsm_groups
end

# Helper: get functions from config
function __fish_devsm_functions
    devsm self complete functions 2>/dev/null
end

# Helper: get tags from config
function __fish_devsm_tags
    devsm self complete tags 2>/dev/null
end

# Helper: get profiles for current token's task
function __fish_devsm_profiles_for_token
    set -l task (__fish_devsm_task_from_token)
    if test -n "$task"
        devsm self complete profiles --task=$task 2>/dev/null
    end
end

# Helper: get variables for a task (outputs completion format)
function __fish_devsm_vars
    set -l cmd (commandline -xpc)
    set -l task (__fish_devsm_current_task_from_tokens $cmd)
    if test -n "$task"
        # Collect already used variables from commandline
        set -l used_vars
        for arg in $cmd
            if string match -q -- '--*=*' "$arg"
                set -l var_name (string match -r -- '^--([^=]+)=' "$arg")[2]
                if test -n "$var_name"
                    set -a used_vars $var_name
                end
            end
        end

        # Build exclude flag if we have used vars
        set -l exclude_flag
        if test (count $used_vars) -gt 0
            set exclude_flag "--exclude="(string join ',' $used_vars)
        end

        devsm self complete vars --task=$task $exclude_flag 2>/dev/null | while read -l line
            set -l parts (string split \t $line)
            set -l name $parts[1]
            set -l desc $parts[2]
            if test -n "$desc"
                printf '%s\t%s\n' "--$name=" "$desc"
            else
                echo "--$name="
            end
        end
    end
end

function __fish_devsm_forwarded_args_from_tokens
    set -l cmd $argv
    set -l command
    set -l command_index
    set -l task_index
    set -l args

    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if not string match -q -- '-*' $arg
            set command $arg
            set command_index $i
            break
        end
    end

    if test -z "$command"
        return 0
    end

    if not __fish_devsm_is_builtin_command $command
        set task_index $command_index
    else if __fish_devsm_is_explicit_task_command $command
        for i in (seq (math $command_index + 1) (count $cmd))
            set -l arg $cmd[$i]
            if not string match -q -- '-*' $arg
                set task_index $i
                break
            end
        end
    else
        return 0
    end

    if test -z "$task_index"
        return 0
    end

    for i in (seq (math $task_index + 1) (count $cmd))
        set -a args $cmd[$i]
    end

    printf '%s\n' $args
end

function __fish_devsm_forwarded_args
    __fish_devsm_forwarded_args_from_tokens (commandline -xpc)
end

function __fish_devsm_emit_task_arg_completions
    set -l cmd (commandline -xpc)
    set -l task (__fish_devsm_current_task_from_tokens $cmd)
    if test -z "$task"
        return 0
    end

    set -l used_vars
    for arg in $cmd
        if string match -q -- '--*=*' "$arg"
            set -l var_name (string match -r -- '^--([^=]+)=' "$arg")[2]
            if test -n "$var_name"
                set -a used_vars $var_name
            end
        end
    end

    set -l exclude_flag
    if test (count $used_vars) -gt 0
        set exclude_flag "--exclude="(string join ',' $used_vars)
    end

    set -l forwarded_args (__fish_devsm_forwarded_args_from_tokens $cmd)
    set -l request_args $forwarded_args
    if string match -qr '\s$' -- (commandline -b)
        set -a request_args ""
    else
        set -l current_token (commandline -ct)
        if test -n "$current_token"
            set -a request_args $current_token
        end
    end

    set -l completion_data (devsm self complete task-args --task=$task $exclude_flag -- $request_args 2>/dev/null)
    if test (count $completion_data) -eq 0
        return 0
    end

    switch $completion_data[1]
        case 'forward'
            if test (count $completion_data) -lt 3
                return 0
            end

            set -l cwd $completion_data[2]
            set -l prefix $completion_data[3..]
            set -l completion_line (string join ' ' (string escape -- $prefix $forwarded_args))
            if string match -qr '\s$' -- (commandline -b)
                set completion_line "$completion_line "
            end

            if pushd "$cwd" >/dev/null 2>/dev/null
                complete -C "$completion_line"
                set -l complete_status $status
                popd >/dev/null 2>/dev/null
                return $complete_status
            end

            complete -C "$completion_line"

        case 'vars'
            for line in $completion_data[2..]
                set -l parts (string split \t -- $line)
                set -l name $parts[1]
                set -l desc $parts[2]
                if test -n "$desc"
                    printf "%s\t%s\n" --$name= $desc
                else
                    echo --$name=
                end
            end

        case 'items'
            for line in $completion_data[2..]
                printf '%s\n' $line
            end
    end
end

# Fish can skip reused dynamic completion actions in some command positions, so
# register copied functions for the explicit and direct task forms.
functions -c __fish_devsm_emit_task_arg_completions __fish_devsm_task_arg_completions
functions -c __fish_devsm_emit_task_arg_completions __fish_devsm_run_task_arg_completions
functions -c __fish_devsm_emit_task_arg_completions __fish_devsm_exec_task_arg_completions
functions -c __fish_devsm_emit_task_arg_completions __fish_devsm_direct_task_arg_completions

# Disable file completions by default
complete -c devsm -f

# Global options
complete -c devsm -n __fish_devsm_needs_command -s h -l help -d 'Print help message'
complete -c devsm -n __fish_devsm_needs_command -rfa '--from=' -d 'Run from DIR instead of current directory'

# Subcommands
complete -c devsm -n __fish_devsm_needs_command -a 'run' -d 'Run a task and display output'
complete -c devsm -n __fish_devsm_needs_command -a 'exec' -d 'Execute task directly, bypassing daemon'
complete -c devsm -n __fish_devsm_needs_command -a 'start' -d 'Start a task via daemon'
complete -c devsm -n __fish_devsm_needs_command -a 'restart' -d 'Restart a task via daemon'
complete -c devsm -n __fish_devsm_needs_command -a 'restart-selected' -d 'Restart selected task in TUI'
complete -c devsm -n __fish_devsm_needs_command -a 'stop' -d 'Terminate a running task'
complete -c devsm -n __fish_devsm_needs_command -a 'test' -d 'Run tests with optional filters'
complete -c devsm -n __fish_devsm_needs_command -a 'rerun-tests' -d 'Rerun tests'
complete -c devsm -n __fish_devsm_needs_command -a 'logs' -d 'View and stream logs'
complete -c devsm -n __fish_devsm_needs_command -a 'get' -d 'Get information from daemon'
complete -c devsm -n __fish_devsm_needs_command -a 'function' -d 'Call a saved function'
complete -c devsm -n __fish_devsm_needs_command -a 'self' -d 'Run devsm self-management commands'
complete -c devsm -n __fish_devsm_needs_command -xa '(__fish_devsm_runnables)'

# Task commands: run, exec, start, restart, stop - only show tasks when we need one
complete -c devsm -n '__fish_devsm_using_command run; and __fish_devsm_needs_task' -xa '(__fish_devsm_runnables)'
complete -c devsm -n '__fish_devsm_using_command exec; and __fish_devsm_needs_task' -xa '(__fish_devsm_tasks)'
complete -c devsm -n '__fish_devsm_using_command start; and __fish_devsm_needs_task' -xa '(__fish_devsm_runnables)'
complete -c devsm -n '__fish_devsm_using_command restart; and __fish_devsm_needs_task' -xa '(__fish_devsm_runnables)'
complete -c devsm -n '__fish_devsm_using_command stop; and __fish_devsm_needs_task' -xa '(__fish_devsm_runnables)'

# Task profiles (task:profile syntax) - when current token contains ':'
complete -c devsm -n '__fish_devsm_using_command run; and __fish_devsm_completing_profile' -xa '(__fish_devsm_profiles_for_token)'
complete -c devsm -n '__fish_devsm_using_command exec; and __fish_devsm_completing_profile' -xa '(__fish_devsm_profiles_for_token)'
complete -c devsm -n '__fish_devsm_using_command start; and __fish_devsm_completing_profile' -xa '(__fish_devsm_profiles_for_token)'
complete -c devsm -n '__fish_devsm_using_command restart; and __fish_devsm_completing_profile' -xa '(__fish_devsm_profiles_for_token)'
complete -c devsm -n '__fish_devsm_using_implicit_task; and __fish_devsm_completing_profile' -xa '(__fish_devsm_profiles_for_token)'

# Start/restart command options
complete -c devsm -n '__fish_devsm_using_command start' -l cached -d 'Only start if not cached'
complete -c devsm -n '__fish_devsm_using_command restart' -l cached -d 'Only restart if not cached'

# Test command
complete -c devsm -n '__fish_devsm_using_command test' -xa '(__fish_devsm_tests)'
complete -c devsm -n '__fish_devsm_using_command test' -xa '(for tag in (__fish_devsm_tags); printf "+%s\tInclude tag\n" $tag; end)'
complete -c devsm -n '__fish_devsm_using_command test' -xa '(for tag in (__fish_devsm_tags); printf "-%s\tExclude tag\n" $tag; end)'
complete -c devsm -n '__fish_devsm_using_command test' -l force -d 'Run tests even when cache would skip them'
complete -c devsm -n '__fish_devsm_using_command test' -l no-cache -d 'Run tests even when cache would skip them'

# Rerun-tests command options
complete -c devsm -n '__fish_devsm_using_command rerun-tests' -l only-failed -d 'Only rerun failed tests'

# Logs command options (use -a with = suffix for flags requiring values, -rfa to disable space after)
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--max-age=' -d 'Show logs since duration ago (5s, 10m, 1h)'
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--task=' -d 'Filter by task name'
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--kind=' -d 'Filter by kind'
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--job=' -d 'Filter by job index'
complete -c devsm -n '__fish_devsm_using_command logs' -s f -l follow -d 'Stream new logs'
complete -c devsm -n '__fish_devsm_using_command logs' -l retry -d 'With @latest, wait for next job'
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--oldest=' -d 'Show oldest N lines'
complete -c devsm -n '__fish_devsm_using_command logs' -rfa '--newest=' -d 'Show newest N lines'
complete -c devsm -n '__fish_devsm_using_command logs' -l without-taskname -d 'Omit task name prefixes'

# Self command
function __fish_devsm_self_needs_subcommand
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if test "$arg" = "self"
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $cmd)
                set -l next_arg $cmd[$next_idx]
                if not string match -q -- '-*' $next_arg
                    return 1
                end
            end
            return 0
        end
    end
    return 1
end

function __fish_devsm_using_self_subcommand
    set -l target $argv[1]
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if test "$arg" = "self"
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $cmd)
                test "$cmd[$next_idx]" = "$target"
                return $status
            end
            return 1
        end
    end
    return 1
end

complete -c devsm -n '__fish_devsm_using_command self; and __fish_devsm_self_needs_subcommand' -xa 'server' -d 'Start daemon process'
complete -c devsm -n '__fish_devsm_using_command self; and __fish_devsm_self_needs_subcommand' -xa 'validate' -d 'Validate config file'
complete -c devsm -n '__fish_devsm_using_command self; and __fish_devsm_self_needs_subcommand' -xa 'logs' -d 'Retrieve daemon logs'
complete -c devsm -n '__fish_devsm_using_command self; and __fish_devsm_self_needs_subcommand' -xa 'complete' -d 'Output completion data'

complete -c devsm -n '__fish_devsm_using_self_subcommand validate' -l skip-path-checks -d 'Skip validation of pwd paths'
complete -c devsm -n '__fish_devsm_using_self_subcommand validate' -xa '(__fish_complete_path)'
complete -c devsm -n '__fish_devsm_using_self_subcommand logs' -s f -l follow -d 'Tail logs'

# Get command
function __fish_devsm_get_needs_resource
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if test "$arg" = "get"
            # Check if there's already a resource after 'get'
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $cmd)
                set -l next_arg $cmd[$next_idx]
                if not string match -q -- '-*' $next_arg
                    return 1
                end
            end
            return 0
        end
    end
    return 1
end

complete -c devsm -n '__fish_devsm_using_command get; and __fish_devsm_get_needs_resource' -xa 'workspace' -d 'Workspace resources'
complete -c devsm -n '__fish_devsm_using_command get; and __fish_devsm_get_needs_resource' -xa 'default-user-config' -d 'Print default user config'
complete -c devsm -n '__fish_devsm_using_command get; and __fish_devsm_get_needs_resource' -xa 'logged-rust-panics' -d 'Show logged Rust panics'

# Get workspace subcommand - only complete if no subcommand entered yet
function __fish_devsm_get_workspace_needs_subcommand
    set -l cmd (commandline -xpc)
    set -l found_workspace 0
    for arg in $cmd
        if test "$arg" = "workspace"
            set found_workspace 1
        else if test $found_workspace -eq 1
            # Something after workspace - subcommand already entered
            if not string match -q -- '-*' $arg
                return 1
            end
        end
    end
    return (test $found_workspace -eq 1)
end

complete -c devsm -n __fish_devsm_get_workspace_needs_subcommand -xa 'config-path' -d 'Get config file path'

# Function command
function __fish_devsm_function_needs_subcommand
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if test "$arg" = "function"
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $cmd)
                return 1
            end
            return 0
        end
    end
    return 1
end

function __fish_devsm_function_call
    set -l cmd (commandline -xpc)
    string match -q -- '*function*call*' "$cmd"
end

complete -c devsm -n '__fish_devsm_using_command function; and __fish_devsm_function_needs_subcommand' -xa 'call' -d 'Call a function'
complete -c devsm -n __fish_devsm_function_call -xa '(__fish_devsm_functions)'

# Complete command contexts
function __fish_devsm_complete_needs_context
    set -l cmd (commandline -xpc)
    for i in (seq 2 (count $cmd))
        set -l arg $cmd[$i]
        if test "$arg" = "self"
            set -l complete_idx (math $i + 1)
            if test $complete_idx -gt (count $cmd); or test "$cmd[$complete_idx]" != "complete"
                return 1
            end
            set -l context_idx (math $i + 2)
            if test $context_idx -le (count $cmd)
                set -l next_arg $cmd[$context_idx]
                if not string match -q -- '-*' $next_arg
                    return 1
                end
            end
            return 0
        end
    end
    return 1
end

complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'commands' -d 'List commands'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'tasks' -d 'List tasks'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'tests' -d 'List tests'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'profiles' -d 'List profiles for task'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'vars' -d 'List variables for task'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'forward-prefix' -d 'List forwarded autocomplete command prefix'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'task-args' -d 'List task argument completion mode and data'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'groups' -d 'List groups'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'functions' -d 'List functions'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'tags' -d 'List tags'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'get-resources' -d 'List get resources'
complete -c devsm -n '__fish_devsm_using_self_subcommand complete; and __fish_devsm_complete_needs_context' -xa 'kinds' -d 'List task kinds'

complete -c devsm -n '__fish_devsm_using_self_subcommand complete' -rfa '--task=' -d 'Task name for profiles/vars'

# Task variables or forwarded argument completions. These stay last so task
# argument values win over top-level task name completions for in-progress args.
complete -c devsm -n '__fish_devsm_using_command run; and __fish_devsm_has_task' -xa '(__fish_devsm_run_task_arg_completions)'
complete -c devsm -n '__fish_devsm_using_command exec; and __fish_devsm_has_task' -xa '(__fish_devsm_exec_task_arg_completions)'
complete -c devsm -n '__fish_devsm_using_command start; and __fish_devsm_has_task' -xa '(__fish_devsm_vars)'
complete -c devsm -n '__fish_devsm_using_command restart; and __fish_devsm_has_task' -xa '(__fish_devsm_vars)'
complete -c devsm -n '__fish_devsm_using_implicit_task; and __fish_devsm_has_task' -xa '(__fish_devsm_direct_task_arg_completions)'
