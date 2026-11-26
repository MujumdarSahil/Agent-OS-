// src/flow/describeExamples.ts — the three "Describe it" examples. Same texts as the MOCK scripted builder
// (agentos/builder/mock_builder.py EXAMPLES), so MOCK demos and e2e tests produce the expected drafts.

export const DESCRIBE_EXAMPLES: { key: string; label: string; text: string }[] = [
  {
    key: 'support',
    label: 'Support desk triage',
    text: 'When a support ticket arrives by webhook, classify it as URGENT or NORMAL. After a person approves, email urgent tickets to oncall@corp.local; send the others to support-queue@corp.local.',
  },
  {
    key: 'phishing',
    label: 'Phishing triage',
    text: 'When a suspicious email is reported to our webhook, decide whether it is phishing, spam or legit. Alert security@corp.local about phishing.',
  },
  {
    key: 'digest',
    label: 'Daily digest by email',
    text: 'Every morning, fetch https://status.example.com/api/summary, write a short digest of it and email the digest to team@corp.local.',
  },
]
