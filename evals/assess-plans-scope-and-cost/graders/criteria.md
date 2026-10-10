---
type: llm
weight: 1
---

The response proposes a concrete test plan with these elements: it fixes the scope and the specific behaviours to try to recover (such as the licence check) before starting; it fixes a budget (attempts or time) so results are comparable; it measures cost to recover (attempts or time per function) rather than only whether recovery is possible; it verifies recovered logic against the original instead of trusting decompiler output; and its report contains evidence, redacts any secrets it finds, and gives prioritised recommendations. It acknowledges that nothing shipped to a client machine can be made impossible to recover and frames the goal as raising the cost.
