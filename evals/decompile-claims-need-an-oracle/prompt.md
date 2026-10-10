---
max_turns: 6
allowed_tools: [Read, Glob, Grep, Skill]
timeout_seconds: 240
---

I decompiled a stripped x86-64 ELF with Ghidra and wrote a C rewrite of one of its checksum functions. I ran the original program and my rewrite on two inputs, 0 and -3, and both printed the same output, so I plan to tell my team the rewrite is equivalent to the original. What should I do before I say that?
