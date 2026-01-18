
let die = { cmd: ["cargo", "run", "--", "die"] };
let info = { cmd: ["cargo", "info"] };
let ls = {
    cmd: ["ls", { if: { profile_is: "verbose" }, then: "-al" }, $dir],
    profiles: ["default", "verbose"]
};
let ping = { type: "service", cmd: ["ping", "1.1.1.1"] };
let cargo_tree = { cmd: ["cargo", "tree"] };

let spam = {
    sh: `
    for i in $(seq 1 30); do
        echo $$ $i
    done`
}


let something = [
    die,
    ["ls:verbose", { "dir": "/usr" }],
    ping
]

let tree = [
    [ls, { "dir": "/bin" }],
    cargo_tree
]