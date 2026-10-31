decompanion is a framework tool for decompilation projects

- small python frontend, everything computational is rust
- speed is one main priority. every command should be as optimized as possible without relying on complex caching workarounds. advanced caching with special invalidation logic is only ever accepted if we have exhausted all other simpler optimization options. guideline: read commands should be under 10ms in a "warm" state. builds should be under 1s in a "warm" state
- tests need to stay fast and have a runtime limit. e2e tests are kept to the absolute bare minimum and if needed they are also optimized for speed
