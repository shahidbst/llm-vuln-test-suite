# MITRE: AML.T0010
# OWASP: LLM03
# CWE: CWE-749
# SEVERITY: Critical
# DESCRIPTION: Training dataset loaded from unverified source contains poisoned samples, variant 44
# EXPLOIT: Attacker inserts backdoor trigger-response pairs into training dataset

from datasets import load_dataset
# VULNERABLE: loading dataset from community hub without auditing
dataset = load_dataset("community-user/training-data-44")  # may be poisoned
from transformers import Trainer, TrainingArguments, AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("gpt2")
trainer = Trainer(model=model, train_dataset=dataset["train"],
    args=TrainingArguments(output_dir=f"/tmp/finetuned-44", num_train_epochs=3))
trainer.train()  # VULNERABLE: training on unverified data
