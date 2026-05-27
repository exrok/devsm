# Bash completion for devsm
# Install: source <(devsm completions bash)
#      or  copy to ~/.local/share/bash-completion/completions/devsm

# Reconstruct the command-line tokens from COMP_LINE/COMP_POINT, splitting on
# whitespace only so that `task:profile` and `--var=val` stay as single tokens
# regardless of $COMP_WORDBREAKS. Sets globals: _devsm_words (array),
# _devsm_cword (index into _devsm_words), _devsm_cur, _devsm_prev.
__devsm_resolve_words() {
    local line="${COMP_LINE:0:COMP_POINT}"
    # Use read -a to split on $IFS (whitespace by default).
    read -ra _devsm_words <<< "$line"
    if [[ -z "$line" || "${line: -1}" =~ [[:space:]] ]]; then
        _devsm_words+=("")
    fi
    _devsm_cword=$((${#_devsm_words[@]} - 1))
    _devsm_cur="${_devsm_words[_devsm_cword]}"
    if (( _devsm_cword > 0 )); then
        _devsm_prev="${_devsm_words[_devsm_cword - 1]}"
    else
        _devsm_prev=""
    fi
}

__devsm_is_builtin_command() {
    case "$1" in
        global|run|exec|start|restart|restart-selected|stop|test|rerun-tests|logs|get|function|self|completions) return 0 ;;
    esac
    return 1
}

__devsm_is_explicit_task_command() {
    case "$1" in
        run|exec|start|restart|stop) return 0 ;;
    esac
    return 1
}

# Locate the first non-flag word among _devsm_words[1.._devsm_cword-1].
# Sets _devsm_cmd and _devsm_cmd_idx, or leaves them empty.
__devsm_find_command() {
    _devsm_cmd=""
    _devsm_cmd_idx=""
    local i w
    for ((i = 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ "$w" == -* || -z "$w" ]] && continue
        _devsm_cmd="$w"
        _devsm_cmd_idx=$i
        return
    done
}

# Within args after $1 (cmd_idx), find the task argument position for explicit
# task commands. For implicit tasks, the task is at cmd_idx itself.
# Sets _devsm_task (with profile stripped) and _devsm_task_idx.
__devsm_find_task() {
    _devsm_task=""
    _devsm_task_idx=""
    local cmd_idx="$1"
    [[ -z "$cmd_idx" ]] && return
    if ! __devsm_is_builtin_command "${_devsm_words[cmd_idx]}"; then
        _devsm_task="${_devsm_words[cmd_idx]%%:*}"
        _devsm_task_idx="$cmd_idx"
        return
    fi
    if ! __devsm_is_explicit_task_command "${_devsm_words[cmd_idx]}"; then
        return
    fi
    local i w
    for ((i = cmd_idx + 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ "$w" == -* || -z "$w" ]] && continue
        _devsm_task="${w%%:*}"
        _devsm_task_idx=$i
        return
    done
}

__devsm_collect_used_vars() {
    _devsm_used_vars=""
    local sep="" w name i
    for ((i = 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        if [[ "$w" == --*=* ]]; then
            name="${w#--}"
            name="${name%%=*}"
            [[ -n "$name" ]] && { _devsm_used_vars+="${sep}${name}"; sep=","; }
        fi
    done
}

__devsm_forwarded_args() {
    _devsm_forwarded=()
    local task_idx="$1"
    [[ -z "$task_idx" ]] && return
    local i w
    for ((i = task_idx + 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ -z "$w" ]] && continue
        _devsm_forwarded+=("$w")
    done
}

__devsm_read_values() {
    local -n out=$1
    local v _rest
    while IFS=$'\t' read -r v _rest; do
        [[ -n "$v" ]] && out+=("$v")
    done
}

__devsm_emit() {
    local cur="$1"; shift
    mapfile -t COMPREPLY < <(compgen -W "$*" -- "$cur")
}

__devsm_complete_runnables() {
    local items=()
    __devsm_read_values items < <(devsm self complete runnables 2>/dev/null)
    __devsm_emit "$_devsm_cur" "${items[*]}"
}

__devsm_complete_tasks_only() {
    local items=()
    __devsm_read_values items < <(devsm self complete tasks 2>/dev/null)
    __devsm_emit "$_devsm_cur" "${items[*]}"
}

__devsm_complete_profiles() {
    local task="$1"
    local items=()
    __devsm_read_values items < <(devsm self complete profiles --task="$task" 2>/dev/null)
    __devsm_emit "$_devsm_cur" "${items[*]}"
}

__devsm_complete_vars_flag() {
    local task="$1" exclude="$2"
    local names=()
    __devsm_read_values names < <(devsm self complete vars --task="$task" ${exclude:+--exclude="$exclude"} 2>/dev/null)
    local candidates=() n
    for n in "${names[@]}"; do candidates+=("--${n}="); done
    mapfile -t COMPREPLY < <(compgen -W "${candidates[*]}" -- "$_devsm_cur")
    compopt -o nospace 2>/dev/null || true
}

__devsm_complete_task_args() {
    local task="$1" exclude="$2"
    __devsm_forwarded_args "$_devsm_task_idx"
    local input
    input="$(devsm self complete task-args --task="$task" ${exclude:+--exclude="$exclude"} -- "${_devsm_forwarded[@]}" 2>/dev/null)"
    if [[ -z "$input" ]]; then
        __devsm_complete_vars_flag "$task" "$exclude"
        return
    fi
    local mode rest
    mode="${input%%$'\n'*}"
    rest="${input#*$'\n'}"
    case "$mode" in
        items)
            local items=()
            while IFS=$'\t' read -r v _; do
                [[ -n "$v" ]] && items+=("$v")
            done <<< "$rest"
            mapfile -t COMPREPLY < <(compgen -W "${items[*]}" -- "$_devsm_cur")
            ;;
        vars)
            local names=()
            while IFS=$'\t' read -r v _; do
                [[ -n "$v" ]] && names+=("--${v}=")
            done <<< "$rest"
            mapfile -t COMPREPLY < <(compgen -W "${names[*]}" -- "$_devsm_cur")
            compopt -o nospace 2>/dev/null || true
            ;;
        forward)
            local cwd="${rest%%$'\n'*}"
            if [[ -n "$cwd" && -d "$cwd" ]]; then
                local saved="$PWD"
                cd "$cwd" 2>/dev/null && {
                    mapfile -t COMPREPLY < <(compgen -f -- "$_devsm_cur")
                    cd "$saved" 2>/dev/null
                }
            else
                mapfile -t COMPREPLY < <(compgen -f -- "$_devsm_cur")
            fi
            ;;
        *)
            __devsm_complete_vars_flag "$task" "$exclude"
            ;;
    esac
}

__devsm_complete_test() {
    local items=()
    __devsm_read_values items < <(devsm self complete tests 2>/dev/null)
    local tags=()
    __devsm_read_values tags < <(devsm self complete tags 2>/dev/null)
    local t
    for t in "${tags[@]}"; do items+=("+${t}" "-${t}"); done
    items+=("--force" "--no-cache")
    mapfile -t COMPREPLY < <(compgen -W "${items[*]}" -- "$_devsm_cur")
}

__devsm_complete_logs() {
    if [[ "$_devsm_cur" == --kind=* ]]; then
        local items=()
        __devsm_read_values items < <(devsm self complete kinds 2>/dev/null)
        local prefixed=() k
        for k in "${items[@]}"; do prefixed+=("--kind=$k"); done
        mapfile -t COMPREPLY < <(compgen -W "${prefixed[*]}" -- "$_devsm_cur")
        return
    fi
    if [[ "$_devsm_cur" == --task=* ]]; then
        local items=()
        __devsm_read_values items < <(devsm self complete tasks 2>/dev/null)
        local prefixed=() t
        for t in "${items[@]}"; do prefixed+=("--task=$t"); done
        mapfile -t COMPREPLY < <(compgen -W "${prefixed[*]}" -- "$_devsm_cur")
        return
    fi
    local opts="--max-age= --task= --kind= --job= -f --follow --retry --oldest= --newest= --without-taskname"
    mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$_devsm_cur")
    [[ "$_devsm_cur" == --*= ]] && compopt -o nospace 2>/dev/null || true
}

__devsm_complete_self() {
    local cmd_idx="$1"
    local sub="" i w
    for ((i = cmd_idx + 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ "$w" == -* || -z "$w" ]] && continue
        sub="$w"; break
    done
    if [[ -z "$sub" ]]; then
        mapfile -t COMPREPLY < <(compgen -W "server validate logs complete" -- "$_devsm_cur")
        return
    fi
    case "$sub" in
        validate)
            mapfile -t COMPREPLY < <(compgen -W "--skip-path-checks" -f -- "$_devsm_cur")
            ;;
        logs)
            mapfile -t COMPREPLY < <(compgen -W "-f --follow" -- "$_devsm_cur")
            ;;
        complete)
            mapfile -t COMPREPLY < <(compgen -W "commands tasks runnables tests profiles vars forward-prefix task-args groups functions tags get-resources kinds --task= --exclude=" -- "$_devsm_cur")
            [[ "$_devsm_cur" == --*= ]] && compopt -o nospace 2>/dev/null || true
            ;;
    esac
}

__devsm_complete_get() {
    local cmd_idx="$1"
    local resource="" i w
    for ((i = cmd_idx + 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ "$w" == -* || -z "$w" ]] && continue
        resource="$w"; break
    done
    if [[ -z "$resource" ]]; then
        local items=()
        __devsm_read_values items < <(devsm self complete get-resources 2>/dev/null)
        __devsm_emit "$_devsm_cur" "${items[*]}"
        return
    fi
    case "$resource" in
        workspace) mapfile -t COMPREPLY < <(compgen -W "config-path" -- "$_devsm_cur") ;;
        workspaces) mapfile -t COMPREPLY < <(compgen -W "--json" -- "$_devsm_cur") ;;
    esac
}

__devsm_complete_function() {
    local cmd_idx="$1"
    local sub="" i w
    for ((i = cmd_idx + 1; i < _devsm_cword; i++)); do
        w="${_devsm_words[i]}"
        [[ "$w" == -* || -z "$w" ]] && continue
        sub="$w"; break
    done
    if [[ -z "$sub" ]]; then
        mapfile -t COMPREPLY < <(compgen -W "call" -- "$_devsm_cur")
        return
    fi
    if [[ "$sub" == "call" ]]; then
        local items=()
        __devsm_read_values items < <(devsm self complete functions 2>/dev/null)
        __devsm_emit "$_devsm_cur" "${items[*]}"
    fi
}

_devsm() {
    COMPREPLY=()
    local _devsm_words _devsm_cword _devsm_cur _devsm_prev
    __devsm_resolve_words

    local _devsm_cmd _devsm_cmd_idx _devsm_task _devsm_task_idx _devsm_used_vars
    local _devsm_forwarded
    __devsm_find_command

    if [[ -z "$_devsm_cmd" ]]; then
        local items=()
        __devsm_read_values items < <(devsm self complete commands 2>/dev/null)
        __devsm_read_values items < <(devsm self complete runnables 2>/dev/null)
        __devsm_emit "$_devsm_cur" "${items[*]}"
        return
    fi

    case "$_devsm_cmd" in
        completions)
            mapfile -t COMPREPLY < <(compgen -W "bash fish zsh" -- "$_devsm_cur")
            return
            ;;
        global|restart-selected)
            return
            ;;
        rerun-tests)
            mapfile -t COMPREPLY < <(compgen -W "--only-failed" -- "$_devsm_cur")
            return
            ;;
        test)
            __devsm_complete_test
            return
            ;;
        logs)
            __devsm_complete_logs
            return
            ;;
        self)
            __devsm_complete_self "$_devsm_cmd_idx"
            return
            ;;
        get)
            __devsm_complete_get "$_devsm_cmd_idx"
            return
            ;;
        function)
            __devsm_complete_function "$_devsm_cmd_idx"
            return
            ;;
        stop)
            __devsm_find_task "$_devsm_cmd_idx"
            if [[ -z "$_devsm_task_idx" ]]; then
                if [[ "$_devsm_cur" == *:* ]]; then
                    __devsm_complete_profiles "${_devsm_cur%%:*}"
                else
                    __devsm_complete_runnables
                fi
            fi
            return
            ;;
        start|restart)
            __devsm_find_task "$_devsm_cmd_idx"
            if [[ -z "$_devsm_task_idx" ]]; then
                if [[ "$_devsm_cur" == *:* ]]; then
                    __devsm_complete_profiles "${_devsm_cur%%:*}"
                else
                    __devsm_complete_runnables
                fi
                return
            fi
            __devsm_collect_used_vars
            __devsm_complete_vars_flag "$_devsm_task" "$_devsm_used_vars"
            ;;
        run)
            __devsm_find_task "$_devsm_cmd_idx"
            if [[ -z "$_devsm_task_idx" ]]; then
                if [[ "$_devsm_cur" == *:* ]]; then
                    __devsm_complete_profiles "${_devsm_cur%%:*}"
                else
                    __devsm_complete_runnables
                fi
                return
            fi
            __devsm_collect_used_vars
            __devsm_complete_task_args "$_devsm_task" "$_devsm_used_vars"
            ;;
        exec)
            __devsm_find_task "$_devsm_cmd_idx"
            if [[ -z "$_devsm_task_idx" ]]; then
                if [[ "$_devsm_cur" == *:* ]]; then
                    __devsm_complete_profiles "${_devsm_cur%%:*}"
                else
                    __devsm_complete_tasks_only
                fi
                return
            fi
            __devsm_collect_used_vars
            __devsm_complete_task_args "$_devsm_task" "$_devsm_used_vars"
            ;;
        *)
            __devsm_find_task "$_devsm_cmd_idx"
            if [[ -n "$_devsm_task" ]]; then
                __devsm_collect_used_vars
                __devsm_complete_task_args "$_devsm_task" "$_devsm_used_vars"
            fi
            ;;
    esac
}

complete -F _devsm devsm
