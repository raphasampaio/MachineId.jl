module MachineId

using SHA

export machine_id, protected_id

function _protect(app_id::AbstractString, id::AbstractString)
    # HMAC-SHA256 with KEY = machine id bytes, MESSAGE = app id bytes; lowercase hex.
    # Key must be a Vector{UInt8} (codeunits returns a read-only CodeUnits).
    return bytes2hex(hmac_sha256(Vector{UInt8}(id), app_id))
end

function _read_file(path::AbstractString)
    contents = read(path, String)
    if isempty(contents)
        return error("file is empty")
    end
    return contents
end

function _cgroup()
    # A missing/short read throws (IO / BoundsError) and is caught by the caller.
    return String(split(read("/proc/self/cgroup", String), "/")[3])
end

function _mount_info()
    contents = read("/proc/self/mountinfo", String)
    if !occursin("docker", contents)
        return error("environment is not a docker container")
    end
    m = match(r"/docker/containers/([a-f0-9]+)/hostname", contents)
    if isnothing(m)
        return error("no docker mountinfo found")
    end
    return String(m.captures[1])
end

function _machine_id_linux()
    # First source that yields a non-empty value wins; a source may throw or
    # return "" to signal "unavailable".
    for source in (
        () -> _read_file("/var/lib/dbus/machine-id"),
        () -> _read_file("/etc/machine-id"),
        _cgroup,
        _mount_info,
    )
        try
            value = source()
            isempty(value) || return strip(value)
        catch
        end
    end
    return error("no machine-id found")
end

function _machine_id_apple()
    output = read(`/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice`, String)
    for line in split(output, "\n")
        if occursin("IOPlatformUUID", line)
            m = match(r"\"IOPlatformUUID\"\s*=\s*\"([^\"]+)\"", line)
            if !isnothing(m)
                return strip(m.captures[1])
            end
        end
    end
    return error("Failed to extract 'IOPlatformUUID' value from `ioreg` output.\n$output")
end

function _machine_id_windows()
    # Go reads the raw registry value (no trim); reg.exe output needs the column
    # padding / trailing CR stripped, which yields the identical canonical GUID.
    # `/reg:64` mirrors WOW64_64KEY; "REG_SZ" and "MachineGuid" are not localized.
    output = read(`reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid /reg:64`, String)
    for line in split(output, "\n")
        if occursin("MachineGuid", line)
            parts = split(line, "REG_SZ")
            if length(parts) >= 2
                return String(strip(parts[end]))
            end
        end
    end
    return error("could not read MachineGuid from registry")
end

"""
    machine_id() -> String

Return the platform-native machine id (a GUID/UUID or dbus machine-id string),
read from OS-native sources without any hardware fingerprinting.

Throws if the machine id cannot be determined (an `ErrorException`, or the
underlying OS/IO error).
"""
function machine_id()
    @static if Sys.iswindows()
        return String(_machine_id_windows())
    elseif Sys.isapple()
        return String(_machine_id_apple())
    elseif Sys.islinux()
        return String(_machine_id_linux())
    else
        return error("unsupported platform")
    end
end

"""
    protected_id(app_id::AbstractString) -> String

Return an app-scoped, non-reversible machine id: the lowercase hex HMAC-SHA256 of
`app_id` keyed by [`machine_id`](@ref) (64 characters). Use this instead of
[`machine_id`](@ref) so the raw machine id never leaves the machine.
"""
function protected_id(app_id::AbstractString)
    return _protect(app_id, machine_id())
end

end
