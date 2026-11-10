# Risky infrastructure settings (Snyk IaC)

**The problem:** infrastructure files describe what gets deployed: Terraform (`.tf`), Kubernetes
manifests, CloudFormation templates and Azure ARM templates. One wrong setting there can expose
everything the code protects, for example a storage bucket anyone can read, or a database port
open to the whole internet. Snyk IaC reads these files and names the setting at fault.

**How to read a finding:** each one gives the file and line, the resource path (such as
`resource.aws_s3_bucket[data].acl`), what's wrong, why it matters, and Snyk's suggested fix. The
report links to Snyk's rule page, which shows a corrected example.

**The fix:** change the setting to the safe value. Don't delete the resource or silence the rule.

```hcl
# Before: anyone on the internet can read the bucket
resource "aws_s3_bucket" "data" {
  bucket = "orders-data"
  acl    = "public-read"
}

# After: private, with public access blocked at the bucket level
resource "aws_s3_bucket" "data" {
  bucket = "orders-data"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

```hcl
# Before: database reachable from anywhere
cidr_blocks = ["0.0.0.0/0"]

# After: only from the application's own network
cidr_blocks = [var.app_subnet_cidr]
```

```yaml
# Kubernetes. Before: the container can do anything the host can
securityContext:
  privileged: true

# After: no extra powers, not root, read-only filesystem
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  readOnlyRootFilesystem: true
```

**Common findings and their usual fix:**

| Finding | Usual fix |
|---|---|
| Storage publicly readable or writable | Make it private; block public access |
| Port open to `0.0.0.0/0` (SSH 22, databases 5432/3306/27017) | Limit to known networks or a bastion |
| Encryption at rest off | Turn on the provider's encryption setting |
| Logging or versioning off | Turn it on, so incidents can be investigated |
| Container privileged, runs as root, or has no resource limits | Set `securityContext` and `resources.limits` |
| Image tag `latest` | Pin a specific version or digest |

**Ask before changing** anything that alters who can reach a running service (network rules,
public endpoints): the person may know of a client that depends on it. Explain what the change
blocks, then let them decide.

If a setting must stay as it is for now (for example a public website bucket that is meant to be
public), record it as an exception with the reason and an owner (`exceptions.md`), rather than
leaving the finding unexplained.
