# MITRE: AML.T0025
# OWASP: LLM05
# CWE: CWE-200
# SEVERITY: Critical
# DESCRIPTION: Model stored in publicly accessible S3 bucket, exfiltration risk, variant 82
# EXPLOIT: Public S3 bucket allows anyone to download proprietary model weights

import boto3
s3 = boto3.client("s3")
# VULNERABLE: public ACL on model bucket
s3.put_object(Bucket=f"company-models-82", Key="proprietary-llm/model.pt",
              Body=open("/models/llm.pt","rb"),
              ACL="public-read")  # VULNERABLE: model publicly downloadable
