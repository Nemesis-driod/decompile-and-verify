# Contributing

The most useful contributions are failures turned into guidance.

- **A route report**: whether a documented route worked for you, with the tool and version you ran. Good and bad results both help; use the "Route report" issue form.
- **A gotcha**: something an agent got wrong, with how you noticed and what fixed it. Add one line to the Gotchas section of `skills/decompile-and-verify/SKILL.md`, or a longer note in the matching reference file.
- **A route**: commands for a target type that is missing or wrong. Say which tool version you ran and whether you ran it; `routes.md` keeps a status table.
- **A script fix**: add a test in `tests/` that fails before your change.
- **An eval case**: `claude plugin eval` runs the cases in `evals/`. Grade outcomes, not tool calls, and keep at least one should-not-fire case.

Keep it lean. If the model already knows it, leave it out. Run `python3 -m unittest discover -s tests -v` before opening a pull request. Please do not attach binaries you do not have the right to share.
