decompanion is a framework tool for decompilation projects

Core Design Principles:
- Every address of the target to decompile gets mapped over time and
we can always ask the tool: "What is at the address in the target?". At
the start of a project all addresses are unknown and over time more and more will become known. Once the decompilation is finished and everything is byte matched, the tooling will have the correct mapping of every address.
- To map these addresses decompanion will provide as much tooling as possible. It will also do its best to identify contradictions in the mapping.

Core Tech Principles:
- small python frontend, everything computational is rust
- speed is one main priority. every command should be as optimized as possible without relying on complex caching workarounds. advanced caching with special invalidation logic is only ever accepted if we have exhausted all other simpler optimization options. guideline: read commands should be under 10ms in a "warm" state. builds should be under 1s in a "warm" state
- tests need to stay fast and have a runtime limit. e2e tests are kept to the absolute bare minimum and if needed they are also optimized for speed
