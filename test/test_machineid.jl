module TestMachineId

using MachineId
using Test

@testset "MachineId" begin
    @testset "protect (known-answer)" begin
        # Go test vector: KEY = machine id, MESSAGE = app id. Cross-checked with OpenSSL.
        expected = "4cd4e275febc906fd1d30145788db96141de9eb986457cccbd80d49402bc8286"
        got = MachineId._protect("ms.azur.appX", "1a1238d601ad430cbea7efb0d1f3d92d")
        @test got == expected
        @test length(got) == 64
        @test occursin(r"^[0-9a-f]{64}$", got)
    end

    @testset "machine_id (integration)" begin
        # Linux (/etc/machine-id) and Windows (registry) should always succeed on CI.
        if Sys.iswindows() || Sys.islinux()
            id = MachineId.machine_id()
            @test id isa String
            @test !isempty(id)
        else
            # Other platforms: tolerate an unavailable source without failing CI.
            try
                id = MachineId.machine_id()
                @test id isa String
                @test !isempty(id)
            catch err
                @test err isa ErrorException
                @info "machine_id() unavailable on this platform" exception = err
            end
        end
    end

    @testset "protected_id (integration)" begin
        if Sys.iswindows() || Sys.islinux()
            pid = MachineId.protected_id("MachineId.jl.test")
            @test length(pid) == 64
            @test occursin(r"^[0-9a-f]{64}$", pid)
            @test pid == MachineId.protected_id("MachineId.jl.test")  # deterministic
        end
    end
end

end
