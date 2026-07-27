var metadata = {
    name: "PowerPick-BOF",
    description: "Host Windows PowerShell from an inline Adaptix BOF"
};

// Operator-side session import registry. Script bodies are cached on the agent
// by powerpick-load; later powerpick --imports only sends import names.
var powerpick_session_imports = [];
var powerpick_operator_max_bytes = 2 * 1024 * 1024;

function powerpick_require_artifacts(root) {
    let bof_path = root + "_bin/powerpick-probe.x64.o";
    let probe_path = root + "_bin/PowerPickProbe.exe";

    if (!ax.file_exists(bof_path)) {
        throw new Error(`missing BOF: ${bof_path}`);
    }
    if (!ax.file_exists(probe_path)) {
        throw new Error(`missing managed host: ${probe_path}`);
    }

    return {
        bof_path: bof_path,
        probe_path: probe_path
    };
}

function powerpick_b64_raw_bytes(encoded) {
    if (!encoded || encoded.length == 0) {
        return 0;
    }

    let padding = 0;
    if (encoded.length >= 2 &&
        encoded.charAt(encoded.length - 1) == "=" &&
        encoded.charAt(encoded.length - 2) == "=") {
        padding = 2;
    }
    else if (encoded.length >= 1 && encoded.charAt(encoded.length - 1) == "=") {
        padding = 1;
    }

    return Math.floor(encoded.length * 3 / 4) - padding;
}

function powerpick_session_total_bytes() {
    let total = 0;
    for (let index = 0; index < powerpick_session_imports.length; index++) {
        total += powerpick_session_imports[index].bytes;
    }
    return total;
}

function powerpick_session_find(name) {
    let needle = name.toLowerCase();
    for (let index = 0; index < powerpick_session_imports.length; index++) {
        if (powerpick_session_imports[index].name.toLowerCase() == needle) {
            return index;
        }
    }
    return -1;
}

// Derive a session import name from the load command line path.
// e.g. powerpick-load ~/opt/PowerView.ps1 → "powerview"
function powerpick_default_import_name(cmdline) {
    let rest = (cmdline || "").replace(/^\s*powerpick-load\s+/i, "").trim();
    if (rest.length == 0) {
        return "";
    }

    let path = "";
    let quote = rest.charAt(0);
    if (quote == '"' || quote == "'") {
        let end = rest.indexOf(quote, 1);
        if (end > 1) {
            path = rest.substring(1, end);
        }
    } else {
        let match = rest.match(/^(\S+)/);
        if (match) {
            path = match[1];
        }
    }

    if (path.length == 0) {
        return "";
    }

    path = path.replace(/\\/g, "/");
    let slash = path.lastIndexOf("/");
    let base = slash >= 0 ? path.substring(slash + 1) : path;
    let dot = base.lastIndexOf(".");
    if (dot > 0) {
        base = base.substring(0, dot);
    }

    base = base.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
    if (base.length == 0) {
        return "";
    }
    if (base.length > 64) {
        base = base.substring(0, 64);
    }
    return base;
}

function powerpick_session_upsert(name, encoded) {
    let bytes = powerpick_b64_raw_bytes(encoded);
    if (bytes <= 0) {
        throw new Error("session import content is empty");
    }
    if (bytes > powerpick_operator_max_bytes) {
        throw new Error("session import exceeds the 2 MiB operator limit");
    }

    let existing = powerpick_session_find(name);
    let next_total = powerpick_session_total_bytes() + bytes;
    if (existing >= 0) {
        next_total -= powerpick_session_imports[existing].bytes;
    }
    if (next_total > powerpick_operator_max_bytes) {
        throw new Error(
            "session imports would exceed the 2 MiB combined operator limit"
        );
    }

    let entry = {
        name: name,
        encoded: encoded,
        bytes: bytes
    };

    if (existing >= 0) {
        powerpick_session_imports[existing] = entry;
        return "replaced";
    }

    powerpick_session_imports.push(entry);
    return "added";
}

function powerpick_session_remove(name) {
    let existing = powerpick_session_find(name);
    if (existing < 0) {
        return false;
    }
    powerpick_session_imports.splice(existing, 1);
    return true;
}

function powerpick_run_managed(id, cmdline, managed_args, task_message, hook) {
    if (!ax.is64(id)) {
        throw new Error("powerpick currently supports x64 agents only");
    }

    let artifacts = powerpick_require_artifacts(ax.script_dir());
    let probe_bytes = ax.file_read(artifacts.probe_path);
    let bof_params = ax.bof_pack("bytes,cstr", [probe_bytes, managed_args]);
    let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;

    if (hook) {
        ax.execute_alias_hook(id, cmdline, command, task_message, hook);
    }
    else {
        ax.execute_alias(id, cmdline, command, task_message);
    }
}

function powerpick_run_exec(id, cmdline, encoded_script, task_message, use_imports) {
    if (!encoded_script || encoded_script.length == 0) {
        throw new Error("PowerShell script content is empty");
    }

    let command_bytes = powerpick_b64_raw_bytes(encoded_script);
    if (command_bytes > powerpick_operator_max_bytes) {
        throw new Error("command exceeds the 2 MiB operator limit");
    }

    let managed_args = `exec ${encoded_script}`;
    let suffix = "";
    if (use_imports) {
        if (powerpick_session_imports.length == 0) {
            throw new Error("no session imports loaded; run powerpick-load first");
        }
        for (let index = 0; index < powerpick_session_imports.length; index++) {
            managed_args += " " + powerpick_session_imports[index].name;
        }
        suffix = ` +${powerpick_session_imports.length} import(s)`;
    }

    powerpick_run_managed(
        id,
        cmdline,
        managed_args,
        task_message + suffix
    );
}

function powerpick_run_store(id, cmdline, name, encoded_script, task_message, hook) {
    if (!ax.is64(id)) {
        throw new Error("powerpick currently supports x64 agents only");
    }

    let artifacts = powerpick_require_artifacts(ax.script_dir());
    let probe_bytes = ax.file_read(artifacts.probe_path);
    let bof_params = ax.bof_pack(
        "bytes,cstr,bytes",
        [probe_bytes, `store ${name}`, encoded_script]
    );
    let command = `execute bof "${artifacts.bof_path}" ${bof_params}`;

    if (hook) {
        ax.execute_alias_hook(id, cmdline, command, task_message, hook);
    }
    else {
        ax.execute_alias(id, cmdline, command, task_message);
    }
}

function powerpick_run_drop(id, cmdline, names, task_message) {
    let managed_args = "drop";
    for (let index = 0; index < names.length; index++) {
        managed_args += " " + names[index];
    }

    powerpick_run_managed(id, cmdline, managed_args, task_message);
}

var cmd_powerpick = ax.create_command(
    "powerpick",
    "Run PowerShell in the agent process via the inline BOF host",
    "powerpick [--imports] <powershell>"
);
cmd_powerpick.addArgBool(
    "--imports",
    "Re-apply all session-loaded scripts before the expression"
);
cmd_powerpick.addArgString(
    "powershell",
    true,
    "PowerShell command or expression to run"
);

cmd_powerpick.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let powershell = parsed_json["powershell"];
    if (!powershell || powershell.length == 0) {
        throw new Error("PowerShell command is empty");
    }

    let encoded_script = ax.encode_data("base64", powershell);
    powerpick_run_exec(
        id,
        cmdline,
        encoded_script,
        "Task: PowerShell (powerpick)",
        !!parsed_json["--imports"]
    );
});

var cmd_powerpick_load = ax.create_command(
    "powerpick-load",
    "Load a local PowerShell script into the session and cache it on the agent",
    "powerpick-load <script.ps1> [name]"
);
cmd_powerpick_load.addArgFile(
    "script",
    true,
    "Local path to a PowerShell script (.ps1) that defines functions"
);
cmd_powerpick_load.addArgString(
    "name",
    false,
    "Optional session import name (default: script basename)"
);

cmd_powerpick_load.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let encoded_script = parsed_json["script"];
    if (!encoded_script || encoded_script.length == 0) {
        throw new Error("session import content is empty");
    }

    let name = parsed_json["name"];
    if (!name || name.length == 0) {
        name = powerpick_default_import_name(cmdline);
    }
    if (!name || name.length == 0) {
        name = "module-" + (powerpick_session_imports.length + 1);
    }
    name = name.toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(name)) {
        throw new Error(
            "session import name must be 1-64 letters, digits, '.', '_' or '-'"
        );
    }

    let bytes = powerpick_b64_raw_bytes(encoded_script);
    if (bytes <= 0) {
        throw new Error("session import content is empty");
    }
    if (bytes > powerpick_operator_max_bytes) {
        throw new Error("session import exceeds the 2 MiB operator limit");
    }

    let existing = powerpick_session_find(name);
    let next_total = powerpick_session_total_bytes() + bytes;
    if (existing >= 0) {
        next_total -= powerpick_session_imports[existing].bytes;
    }
    if (next_total > powerpick_operator_max_bytes) {
        throw new Error(
            "session imports would exceed the 2 MiB combined operator limit"
        );
    }

    let pending_name = name;
    let pending_encoded = encoded_script;
    let action = existing >= 0 ? "replaced" : "added";

    let hook = function (task) {
        if (!task.completed) {
            return task;
        }

        let failed =
            task.type == "error" ||
            /failed to store|requires a name/i.test(task.text || "");

        if (failed) {
            if (task.message == "") {
                task.message = `Session import '${pending_name}' push rejected`;
            }
            return task;
        }

        powerpick_session_upsert(pending_name, pending_encoded);
        if (task.message == "") {
            task.message =
                `Session import '${pending_name}' ${action} and cached on agent ` +
                `(${powerpick_session_imports.length} loaded, ` +
                `${powerpick_session_total_bytes()} bytes)`;
        }

        return task;
    };

    powerpick_run_store(
        id,
        cmdline,
        name,
        encoded_script,
        `Task: cache session import (${name}, ${bytes} bytes)`,
        hook
    );
});

var cmd_powerpick_loads = ax.create_command(
    "powerpick-loads",
    "List PowerShell scripts currently loaded in the session",
    "powerpick-loads"
);

cmd_powerpick_loads.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (powerpick_session_imports.length == 0) {
        ax.console_message(
            id,
            "No session imports loaded\n",
            "info",
            "Use powerpick-load SCRIPT [name] to add one."
        );
        return;
    }

    let lines = "";
    for (let index = 0; index < powerpick_session_imports.length; index++) {
        let item = powerpick_session_imports[index];
        lines += `${index + 1}. ${item.name} (${item.bytes} bytes)\n`;
    }
    lines +=
        `Total: ${powerpick_session_imports.length} import(s), ` +
        `${powerpick_session_total_bytes()} bytes\n`;

    ax.console_message(
        id,
        `Session imports (${powerpick_session_imports.length})\n`,
        "info",
        lines
    );
});

var cmd_powerpick_unload = ax.create_command(
    "powerpick-unload",
    "Remove a cached session import by name, or clear all imports",
    "powerpick-unload <name|all>"
);
cmd_powerpick_unload.addArgString(
    "name",
    true,
    "Import name to drop, or 'all' to clear every session import"
);

cmd_powerpick_unload.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name = parsed_json["name"];
    if (!name || name.length == 0) {
        throw new Error("session import name is required");
    }
    name = name.toLowerCase();

    if (name == "all") {
        let names = [];
        for (let index = 0; index < powerpick_session_imports.length; index++) {
            names.push(powerpick_session_imports[index].name);
        }
        powerpick_session_imports = [];
        if (names.length == 0) {
            ax.console_message(id, "No session imports to clear\n", "info");
            return;
        }
        powerpick_run_drop(
            id,
            cmdline,
            names,
            `Task: drop ${names.length} cached session import(s)`
        );
        return;
    }

    if (!powerpick_session_remove(name)) {
        throw new Error(`session import '${name}' is not loaded`);
    }

    powerpick_run_drop(
        id,
        cmdline,
        [name],
        `Task: drop cached session import (${name})`
    );
});

var group_powerpick = ax.create_commands_group(
    "PowerPick-BOF",
    [
        cmd_powerpick,
        cmd_powerpick_load,
        cmd_powerpick_loads,
        cmd_powerpick_unload
    ]
);

ax.register_commands_group(
    group_powerpick,
    ["beacon", "gopher", "kharon"],
    ["windows"],
    []
);
