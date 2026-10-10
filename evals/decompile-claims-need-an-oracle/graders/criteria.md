---
type: llm
weight: 1
---

The response treats two matching inputs as insufficient evidence of equivalence. It recommends checking against the original with a stronger check: boundary inputs (zero, negative, maximum, empty, values around every comparison in the code) and many more inputs, or a differential or instruction-matching comparison. It says the claim should be limited to what was tested (for example "equivalent on N inputs") or marked unverified. It does not tell the user the rewrite is already proven equivalent.
