"""injeval: a small evaluation harness for prompt-injection, jailbreak,
exfiltration and tool-call abuse attacks against an LLM deployment,
with a rule-based input detector and an output filter in front of it.

Pipeline per attack case:

    attack prompt
        -> input detector  (block / allow, with the rules that fired)
        -> target model    (mock, Ollama, Bedrock)
        -> output filter   (canary leak, success marker, forbidden tool call)
        -> judgement       (did the attack reach its goal?)

Metrics reported per attack class and overall:

    ASR_raw        attack success rate with no defences
    ASR_input      with the input detector blocking flagged prompts
    ASR_both       with the input detector and the output filter
    FP_rate        fraction of benign prompts the input detector blocks
"""

__version__ = "0.1.0"
