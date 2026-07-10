# MachineId.jl

[![CI](https://github.com/raphasampaio/MachineId.jl/actions/workflows/CI.yml/badge.svg)](https://github.com/raphasampaio/MachineId.jl/actions/workflows/CI.yml)
[![codecov](https://codecov.io/gh/raphasampaio/MachineId.jl/graph/badge.svg?token=J7W7bDeEpi)](https://codecov.io/gh/raphasampaio/MachineId.jl)
[![Aqua](https://raw.githubusercontent.com/JuliaTesting/Aqua.jl/master/badge.svg)](https://github.com/JuliaTesting/Aqua.jl)

## Introduction

MachineId.jl returns a stable, unique identifier for the host machine, read from OS-native sources (no hardware fingerprinting). It also provides protected id, an app-scoped HMAC-SHA256 of the machine id, so you can identify a machine without ever exposing the raw id. This is a Julia portof the Go library [`keygen-sh/machineid`](https://github.com/keygen-sh/machineid).

## Getting Started

### Installation

```julia
pkg> add MachineId
```

### Example

```julia
using MachineId

# The raw machine id (e.g. "23339b15-c1ee-4011-a1d3-88aab8a341d3")
machine_id()

# An app-scoped id that never exposes the raw machine id (64-char lowercase hex)
protected_id("Corp.SomeApp")
```

Both functions throw if the machine id cannot be determined.

## Contributing

Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.