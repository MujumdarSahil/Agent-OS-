# Training Datasets

## SFT Dataset Format

SFT (Supervised Fine-Tuning) datasets should be in JSON format:

```json
[
  {
    "instruction": "Analyze this firewall rule",
    "input": "Firewall rule: allow 0.0.0.0/0 to port 22",
    "output": "This firewall rule is insecure because it allows SSH access from any IP address."
  }
]
```

## Sample Dataset

See `sample_sft_dataset.json` for a small example dataset.

## Safety Considerations

- Only use ethical and legal training data
- No private or sensitive information
- No exploit code or malware examples
- Focus on defensive security operations

