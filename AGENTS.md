decompanion is a framework tool for decompilation projects

Core Design Principles:
- Every address of the target to decompile gets mapped over time and
we can always ask the tool: "What is at the address in the target?". At
the start of a project all addresses are unknown and over time more and more will become known. Once the decompilation is finished and everything is byte matched, the tooling will have the correct mapping of every address.
- To map these addresses decompanion will provide as much tooling as possible. It will also do its best to identify contradictions in the mapping.
- The model behind this is docs/mental-model.md: H (our source and toolchain), I (the image), φ (which object of H is which part of I), claims with their support, answers, findings (contradiction, ill-formed, gap, stale, debt), experiments, exceptions and debt. The code and the command line use its names; a new concept is placed in it first.

Core Tech Principles:
- pure Rust: one binary `dcp` (the command line, the client and the project's daemon); the core does the computing, the CLI parses, refreshes and prints
- speed is one main priority. every command should be as optimized as possible without relying on complex caching workarounds. advanced caching with special invalidation logic is only ever accepted if we have exhausted all other simpler optimization options. guideline: read commands should be under 10ms in a "warm" state. builds should be under 1s in a "warm" state
- tests need to stay fast and have a runtime limit. e2e tests are kept to the absolute bare minimum and if needed they are also optimized for speed
