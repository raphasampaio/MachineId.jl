module TestAqua

using Aqua
using MachineId
using Test

@testset "Aqua" begin
    Aqua.test_ambiguities(MachineId, recursive = false)
    Aqua.test_all(MachineId, ambiguities = false)
    return nothing
end

end
