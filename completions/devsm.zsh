#compdef devsm
# Zsh completion for devsm
# Install: devsm completions zsh > ~/.zfunc/_devsm
#          then add `fpath+=~/.zfunc` to ~/.zshrc before `compinit`

autoload -U is-at-least

_devsm() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
        '-h[Print help]' \
        '--help[Print help]' \
        '--from=[Run from DIR instead of current directory]:dir:_directories' \
        ':: :_devsm_commands' \
        '*::: :->devsm' \
        && ret=0

    case $state in
    (devsm)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:devsm-command-$line[1]:"
        case $line[1] in
            (run)
                _arguments "${_arguments_options[@]}" : \
                    ':task:_devsm_runnables' \
                    '*::arg:_devsm_task_args' \
                    && ret=0
                ;;
            (exec)
                _arguments "${_arguments_options[@]}" : \
                    ':task:_devsm_tasks_only' \
                    '*::arg:_devsm_task_args' \
                    && ret=0
                ;;
            (start|restart)
                _arguments "${_arguments_options[@]}" : \
                    '--cached[Skip restart if task has cache support and key matches]' \
                    ':task:_devsm_runnables' \
                    '*::arg:_devsm_vars_only' \
                    && ret=0
                ;;
            (stop)
                _arguments "${_arguments_options[@]}" : \
                    ':task:_devsm_runnables' \
                    && ret=0
                ;;
            (status)
                _arguments "${_arguments_options[@]}" : \
                    ':task:_devsm_runnables' \
                    && ret=0
                ;;
            (test)
                _arguments "${_arguments_options[@]}" : \
                    '--force[Run tests even when cache would skip them]' \
                    '--no-cache[Run tests even when cache would skip them]' \
                    '*::filter:_devsm_test_filters' \
                    && ret=0
                ;;
            (rerun-tests)
                _arguments "${_arguments_options[@]}" : \
                    '--only-failed[Only rerun failed tests]' \
                    && ret=0
                ;;
            (logs)
                _arguments "${_arguments_options[@]}" : \
                    '--max-age=[Show logs since duration ago (5s, 10m, 1h)]:duration:' \
                    '*--task=[Filter by task name]:task:_devsm_tasks_only' \
                    '*--kind=[Filter by kind]:kind:_devsm_kinds' \
                    '--job=[Filter by job index]:index:' \
                    '(-f --follow)'{-f,--follow}'[Stream new logs]' \
                    '--retry[With @latest, wait for next job]' \
                    '--oldest=[Show oldest N lines]:N:' \
                    '--newest=[Show newest N lines]:N:' \
                    '--without-taskname[Omit task name prefixes]' \
                    '*::pattern:' \
                    && ret=0
                ;;
            (self)
                _arguments "${_arguments_options[@]}" : \
                    ':: :_devsm_self_commands' \
                    '*::: :->self' \
                    && ret=0
                case $state in
                (self)
                    case $line[1] in
                        (server)
                            _arguments "${_arguments_options[@]}" && ret=0
                            ;;
                        (validate)
                            _arguments "${_arguments_options[@]}" : \
                                '--skip-path-checks[Skip validation of pwd paths]' \
                                ':path:_files' \
                                && ret=0
                            ;;
                        (logs)
                            _arguments "${_arguments_options[@]}" : \
                                '(-f --follow)'{-f,--follow}'[Tail logs]' \
                                && ret=0
                            ;;
                        (complete)
                            _arguments "${_arguments_options[@]}" : \
                                '--task=[Task name for profiles/vars]:task:_devsm_tasks_only' \
                                '--exclude=[Excluded variables]:vars:' \
                                ':context:(commands tasks runnables tests profiles vars forward-prefix task-args groups functions tags get-resources kinds)' \
                                && ret=0
                            ;;
                    esac
                    ;;
                esac
                ;;
            (get)
                _arguments "${_arguments_options[@]}" : \
                    ':: :_devsm_get_resources' \
                    '*::: :->get' \
                    && ret=0
                case $state in
                (get)
                    case $line[1] in
                        (workspace)
                            _arguments "${_arguments_options[@]}" : \
                                ':sub:(config-path)' \
                                && ret=0
                            ;;
                        (workspaces)
                            _arguments "${_arguments_options[@]}" : \
                                '--json[Output JSON]' \
                                && ret=0
                            ;;
                    esac
                    ;;
                esac
                ;;
            (function)
                _arguments "${_arguments_options[@]}" : \
                    ':sub:(call)' \
                    ':fn:_devsm_functions' \
                    && ret=0
                ;;
            (completions)
                _arguments "${_arguments_options[@]}" : \
                    ':shell:(bash fish zsh)' \
                    && ret=0
                ;;
            (global|restart-selected)
                _arguments "${_arguments_options[@]}" && ret=0
                ;;
            (*)
                _devsm_task_args
                ret=0
                ;;
        esac
        ;;
    esac

    return ret
}

# Convert tab-separated value\tdescription lines into _describe-compatible
# 'value:description' format, escaping ':' that appear inside the value.
_devsm_tab_pairs() {
    awk -F'\t' '{
        v = $1
        gsub(/:/, "\\:", v)
        if (NF >= 2 && length($2) > 0) print v ":" $2
        else print v
    }'
}

_devsm_commands() {
    local -a commands
    commands=(
        'global:Open global workspace selector'
        'run:Run a task and display output'
        'exec:Execute task directly, bypassing daemon'
        'start:Start a task via daemon'
        'restart:Restart a task via daemon'
        'restart-selected:Restart selected task in TUI'
        'stop:Terminate a running task'
        'status:Show active tasks or task/group status'
        'test:Run tests with optional filters'
        'rerun-tests:Rerun previously failed tests'
        'logs:View and stream logs'
        'get:Get information from daemon'
        'function:Call a saved function'
        'self:Run devsm self-management commands'
        'completions:Print shell completion script'
    )
    _describe -t commands 'command' commands
    _devsm_runnables
}

_devsm_runnables() {
    local -a items
    items=("${(@f)$(devsm self complete runnables 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t runnables 'runnable' items
}

_devsm_tasks_only() {
    local -a items
    items=("${(@f)$(devsm self complete tasks 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t tasks 'task' items
}

_devsm_tests() {
    local -a items
    items=("${(@f)$(devsm self complete tests 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t tests 'test' items
}

_devsm_kinds() {
    local -a items
    items=("${(@f)$(devsm self complete kinds 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t kinds 'kind' items
}

_devsm_functions() {
    local -a items
    items=("${(@f)$(devsm self complete functions 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t functions 'function' items
}

_devsm_self_commands() {
    local -a commands
    commands=(
        'server:Start daemon process'
        'validate:Validate config file'
        'logs:Retrieve daemon logs'
        'complete:Output completion data'
    )
    _describe -t self-commands 'self subcommand' commands
}

_devsm_get_resources() {
    local -a items
    items=("${(@f)$(devsm self complete get-resources 2>/dev/null | _devsm_tab_pairs)}")
    _describe -t resources 'resource' items
}

_devsm_test_filters() {
    _devsm_tests
    local -a items
    local v rest
    while IFS=$'\t' read -r v rest; do
        items+=("+${v}:include tag")
        items+=("-${v}:exclude tag")
    done < <(devsm self complete tags 2>/dev/null)
    _describe -t filters 'tag filter' items
}

_devsm_vars_only() {
    local task="${words[1]%%:*}"
    local -a used_vars
    local w name
    for w in "${words[@]:1}"; do
        if [[ "$w" == --*=* ]]; then
            name="${w#--}"; name="${name%%=*}"
            [[ -n "$name" ]] && used_vars+=("$name")
        fi
    done
    local exclude=""
    (( ${#used_vars[@]} > 0 )) && exclude="${(j:,:)used_vars}"

    local -a items
    local v desc
    while IFS=$'\t' read -r v desc; do
        [[ -z "$v" ]] && continue
        if [[ -n "$desc" ]]; then
            items+=("--${v}=:${desc}")
        else
            items+=("--${v}=")
        fi
    done < <(devsm self complete vars --task="$task" ${exclude:+--exclude="$exclude"} 2>/dev/null)
    _describe -t vars 'variable' items
}

_devsm_task_args() {
    local task="${words[1]%%:*}"
    local -a used_vars
    local w name
    for w in "${words[@]:1}"; do
        if [[ "$w" == --*=* ]]; then
            name="${w#--}"; name="${name%%=*}"
            [[ -n "$name" ]] && used_vars+=("$name")
        fi
    done
    local exclude=""
    (( ${#used_vars[@]} > 0 )) && exclude="${(j:,:)used_vars}"

    local -a forwarded
    for w in "${words[@]:2}"; do
        [[ "$w" == --*=* ]] && continue
        [[ -z "$w" ]] && continue
        forwarded+=("$w")
    done

    local mode_data
    mode_data="$(devsm self complete task-args --task="$task" ${exclude:+--exclude="$exclude"} -- "${forwarded[@]}" 2>/dev/null)"
    if [[ -z "$mode_data" ]]; then
        _devsm_vars_only
        return
    fi

    local mode="${mode_data%%$'\n'*}"
    local rest="${mode_data#*$'\n'}"
    case "$mode" in
        (items)
            local -a items
            items=("${(@f)$(printf '%s\n' "$rest" | _devsm_tab_pairs)}")
            _describe -t args 'arg' items
            ;;
        (vars)
            local -a items
            local v desc
            while IFS=$'\t' read -r v desc; do
                [[ -z "$v" ]] && continue
                if [[ -n "$desc" ]]; then
                    items+=("--${v}=:${desc}")
                else
                    items+=("--${v}=")
                fi
            done <<< "$rest"
            _describe -t vars 'variable' items
            ;;
        (forward)
            local cwd="${rest%%$'\n'*}"
            if [[ -n "$cwd" && -d "$cwd" ]]; then
                local saved="$PWD"
                builtin cd "$cwd" 2>/dev/null && { _files; builtin cd "$saved" 2>/dev/null; }
            else
                _files
            fi
            ;;
    esac
}

if [ "$funcstack[1]" = "_devsm" ]; then
    _devsm "$@"
elif (( ${+functions[compdef]} )); then
    compdef _devsm devsm
fi
