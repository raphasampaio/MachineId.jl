module TestMachineId

using MachineId
using Test

@testset "MachineId" begin
    @testset "protect (known-answer)" begin
        # Go test vector: KEY = machine id, MESSAGE = app id. Cross-checked with OpenSSL.
        expected = "4cd4e275febc906fd1d30145788db96141de9eb986457cccbd80d49402bc8286"
        got = MachineId.protect("ms.azur.appX", "1a1238d601ad430cbea7efb0d1f3d92d")
        @test got == expected
        @test length(got) == 64
        @test occursin(r"^[0-9a-f]{64}$", got)
    end

    @testset "parsers (known-answer)" begin
        # Pure parsers run on every OS, so parsing + error branches are covered
        # regardless of which platform the CI job runs on.

        # Windows: reg.exe output (padded columns, trailing CR).
        win = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    1a1238d6-01ad-430c-bea7-efb0d1f3d92d\r\n"
        @test MachineId.parse_windows(win) == "1a1238d6-01ad-430c-bea7-efb0d1f3d92d"
        @test_throws ErrorException MachineId.parse_windows("MachineGuid but no reg type\nother line")

        # Apple: ioreg output.
        apple = "  |   \"IOPlatformUUID\" = \"1A1238D6-01AD-430C-BEA7-EFB0D1F3D92D\"\n"
        @test MachineId.parse_apple(apple) == "1A1238D6-01AD-430C-BEA7-EFB0D1F3D92D"
        @test_throws ErrorException MachineId.parse_apple("no uuid here")

        # Linux cgroup: third "/"-separated segment.
        @test MachineId.parse_cgroup("0::/docker/abc123") == "abc123"
        @test_throws BoundsError MachineId.parse_cgroup("noslash")

        # Linux mountinfo: docker container id.
        mi = "1234 5678 0:1 / / rw - overlay overlay rw\n2000 1234 /docker/containers/deadbeef0123/hostname /etc/hostname rw"
        @test MachineId.parse_mount_info(mi) == "deadbeef0123"
        @test_throws ErrorException MachineId.parse_mount_info("plain mountinfo, no runtime")     # not docker
        @test_throws ErrorException MachineId.parse_mount_info("mentions docker, no hostname path")  # no regex match
    end

    @testset "raw (integration)" begin
        # Linux (/etc/machine-id), Windows (registry), and macOS (ioreg) should
        # always succeed on CI.
        if Sys.iswindows() || Sys.islinux() || Sys.isapple()
            id = MachineId.raw()
            @test id isa String
            @test !isempty(id)
        end
    end

    @testset "protected (integration)" begin
        if Sys.iswindows() || Sys.islinux() || Sys.isapple()
            pid = MachineId.protected("MachineId.jl.test")
            @test length(pid) == 64
            @test occursin(r"^[0-9a-f]{64}$", pid)
            @test pid == MachineId.protected("MachineId.jl.test")  # deterministic
        end
    end
end

end
