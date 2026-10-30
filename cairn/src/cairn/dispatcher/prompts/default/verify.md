# Task
Independently verify the candidate fact below. Use the graph for context, but do not accept the candidate merely because another worker produced it. Check the strongest available evidence, reproduce the observation when possible, and look for a plausible alternative explanation.

# Output Requirements
Return only one raw JSON object.

If the candidate is confirmed:
```json
{"accepted":true,"data":{"verdict":"verified","summary":"why the evidence confirms the fact","evidence":[{"kind":"command|http|file|observation|reference","summary":"independent evidence","artifact_path":"optional path","source_url":"optional URL"}]}}
```

If the candidate is disproved or too weak to use as an objective fact:
```json
{"accepted":true,"data":{"verdict":"rejected","summary":"why the candidate is false, ambiguous, stale, or unsupported","evidence":[]}}
```

# Rules
- A candidate is not verified by repetition. Require evidence that directly supports its key claim.
- Separate observed behavior from inference. Version-only or CVE-name matches need applicability evidence.
- Prefer reproducible commands, protocol responses, file contents, authoritative references, or goal artifacts.
- Do not claim success merely because a tool ran without error.
- Keep evidence summaries concise and store long output in an artifact file.

# Context
## Graph
```
{graph_yaml}
```

## Candidate Fact ID
```
{fact_id}
```

## Candidate Fact
```json
{fact_json}
```
