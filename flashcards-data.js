const flashcards = [
    {
        question: "How do you troubleshoot high memory usage on a Linux server?",
        answer: "First, I identify the scope using `free -h` to see overall memory usage and `vmstat 1 5` for trends. Then I find the culprits with `ps aux --sort=-%mem | head -20` to see top memory consumers. For deeper analysis, I check `/proc/meminfo` for detailed breakdown, use `smem` or `pmap <PID>` to analyze specific processes, and review `dmesg` or `/var/log/messages` for OOM killer activity. I also check for memory leaks using `/proc/<PID>/status` for VmRSS growth over time and consider using `valgrind` for debugging if needed."
    },
    {
        question: "Explain the Linux boot process in detail",
        answer: "The boot process follows: BIOS/UEFI performs POST and loads the bootloader from MBR/GPT. GRUB loads the kernel and initramfs into memory. The kernel initializes hardware, mounts the root filesystem, and starts PID 1 (systemd). Systemd then starts services based on targets/dependencies, mounts remaining filesystems per `/etc/fstab`, initializes networking, and finally reaches the default target (multi-user or graphical)."
    },
    {
        question: "What's the difference between soft and hard links?",
        answer: "Hard links share the same inode number and point directly to the data blocks on disk. They can't cross filesystem boundaries and can't link to directories. Deleting the original file doesn't affect hard links. Soft links (symlinks) are separate files containing a path to the target. They can cross filesystems, link to directories, and break if the target is deleted. Use `ln` for hard links and `ln -s` for soft links."
    },
    {
        question: "How would you diagnose intermittent network connectivity issues?",
        answer: "I'd start with continuous monitoring using `mtr` or `ping` to identify packet loss patterns. Then use `tcpdump` or `wireshark` to capture traffic during issues, check `netstat -s` for protocol statistics and errors, review `ip -s link` for interface errors, and examine firewall rules with `iptables -L -n -v`. I'd also verify MTU issues with `ping -M do -s 1472`, check DNS with `dig` or `nslookup`, and review network configuration consistency."
    },
    {
        question: "Write a Python script to monitor disk usage and alert when it exceeds 80%",
        answer: `\`\`\`python
import psutil
import smtplib
from email.mime.text import MIMEText
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_disk_usage(threshold=80):
    """Monitor disk usage and alert when threshold exceeded"""
    alerts = []
    
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            if usage.percent > threshold:
                alert_msg = f"{partition.mountpoint}: {usage.percent:.1f}% used ({usage.used/1024**3:.1f}GB of {usage.total/1024**3:.1f}GB)"
                alerts.append(alert_msg)
                logger.warning(alert_msg)
        except PermissionError:
            logger.error(f"Permission denied: {partition.mountpoint}")
            
    if alerts:
        send_alert("\\n".join(alerts))
    
def send_alert(message):
    """Send alert via email or webhook"""
    # Implementation depends on alerting infrastructure
    logger.info(f"Alert sent: {message}")
\`\`\``
    },
    {
        question: "How do you handle errors and exceptions in Python production code?",
        answer: "I use structured exception handling with specific exception types, never bare `except:`. I implement proper logging with appropriate levels (ERROR, WARNING, INFO) and use context managers for resource management. For production, I create custom exception classes for domain-specific errors, use `try/except/else/finally` blocks appropriately, log full stack traces for debugging, implement retry logic with exponential backoff for transient failures, and ensure graceful degradation rather than crashes."
    },
    {
        question: "Explain Python's GIL and its implications for multi-threaded applications",
        answer: "The Global Interpreter Lock (GIL) is a mutex that protects access to Python objects, preventing multiple threads from executing Python bytecode simultaneously. This means CPU-bound multi-threaded programs don't achieve true parallelism. For CPU-bound tasks, use multiprocessing instead of threading. For I/O-bound tasks, threading is still effective as GIL is released during I/O operations. Alternatives include using async/await for concurrent I/O or libraries like NumPy that release the GIL during computations."
    },
    {
        question: "How would you debug a container that keeps crashing?",
        answer: "First, check the logs with `docker logs --tail 50 -f <container>` and examine exit codes with `docker inspect <container> | jq '.[0].State'`. Then run the container interactively: `docker run -it --entrypoint /bin/sh <image>` to test commands manually. Check resource constraints with `docker stats`, review the Dockerfile for issues, verify environment variables and secrets, test health checks manually, and check for file permission issues or missing dependencies."
    },
    {
        question: "Explain Kubernetes networking (Services, Ingress, Network Policies)",
        answer: "Kubernetes networking follows these principles: Every pod gets a unique IP address. Containers in a pod share network namespace (localhost). Services provide stable endpoints for pod groups using label selectors and implementing load balancing via iptables or IPVS. Ingress controllers manage external access, providing HTTP/HTTPS routing, SSL termination, and name-based virtual hosting. Network Policies control traffic flow between pods using label selectors to define allowed connections."
    },
    {
        question: "How do you handle secrets in containerized environments?",
        answer: "Never bake secrets into images or commit them to version control. Use dedicated secret management tools like HashiCorp Vault for centralized management, Kubernetes Secrets mounted as volumes or environment variables, or cloud provider solutions (AWS Secrets Manager, Azure Key Vault). Implement secret rotation, use least-privilege access, encrypt secrets at rest and in transit, audit secret access, and use init containers or sidecar patterns for secret injection."
    },
    {
        question: "Design a Terraform module for a highly available web application",
        answer: `\`\`\`hcl
module "ha_web_app" {
  source = "./modules/ha-web-app"
  
  vpc_cidr = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  # ALB Configuration
  alb_settings = {
    internal = false
    deletion_protection = true
    enable_http2 = true
  }
  
  # Auto Scaling Group
  asg_settings = {
    min_size = 3
    max_size = 10
    desired_capacity = 3
    health_check_grace_period = 300
    health_check_type = "ELB"
  }
  
  # RDS Multi-AZ
  database_settings = {
    engine = "postgres"
    instance_class = "db.r5.large"
    multi_az = true
    backup_retention_period = 7
  }
}
\`\`\`

The module includes VPC with public/private subnets across AZs, Application Load Balancer with health checks, Auto Scaling Group with launch templates, RDS Multi-AZ for database HA, CloudWatch alarms and SNS notifications, and Security Groups with least privilege.`
    },
    {
        question: "How do you handle Terraform state file conflicts in a team?",
        answer: "Use remote state backends (S3 with DynamoDB for state locking), implement proper workspace strategies for environments, use consistent naming conventions, implement PR-based workflows with plan output reviews, use `terraform refresh` carefully, implement state backup strategies, and use tools like Atlantis for Terraform automation. Never modify state files manually."
    },
    {
        question: "Design a CI/CD pipeline for a microservices application",
        answer: `\`\`\`yaml
stages:
  - build
  - test
  - security
  - deploy-staging
  - integration-tests
  - deploy-production

build:
  parallel:
    - docker build & push
    - dependency scanning
    - SAST (static analysis)

test:
  parallel:
    - unit tests
    - code coverage (>80%)
    - linting

security:
  - container scanning
  - DAST (dynamic analysis)
  - license compliance

deploy-staging:
  - blue-green deployment
  - smoke tests
  - rollback on failure

integration-tests:
  - API tests
  - performance tests
  - chaos engineering

deploy-production:
  - canary deployment (10% -> 50% -> 100%)
  - monitoring alerts
  - automatic rollback triggers
\`\`\``
    },
    {
        question: "How do you ensure zero-downtime deployments?",
        answer: "Implement blue-green deployments with atomic switches, use rolling updates with proper readiness/liveness probes, ensure backward compatibility for API changes, handle database migrations separately (expand-contract pattern), implement feature flags for gradual rollouts, use connection draining for graceful shutdowns, implement comprehensive health checks, and maintain rollback procedures with tested automation."
    },
    {
        question: "Production is down. Walk me through your response.",
        answer: `**1. Acknowledge**: Join incident channel, acknowledge I'm investigating
**2. Assess**: Check monitoring dashboards, recent deployments, error rates
**3. Communicate**: Update stakeholders every 15 minutes
**4. Investigate**: Form hypothesis, test systematically, check logs/metrics
**5. Mitigate**: Implement fix or rollback, verify resolution
**6. Document**: Create timeline, capture lessons learned
**7. Post-mortem**: Blameless review, action items for prevention`
    },
    {
        question: "How do you handle a 'thundering herd' problem?",
        answer: "Implement exponential backoff with jitter to spread retry attempts, use circuit breakers to prevent cascade failures, implement rate limiting at multiple levels, add caching layers with cache warming, use queue-based load leveling, implement bulkheading to isolate failures, and consider using tokens/leaky bucket algorithms."
    },
    {
        question: "A web service is experiencing 10x normal traffic. How do you handle it?",
        answer: "Immediately scale horizontally if auto-scaling isn't keeping up, enable caching at all levels (CDN, application, database), implement rate limiting to protect core functionality, shed non-critical features, scale database read replicas, optimize expensive queries, enable connection pooling, and communicate with stakeholders about degraded service."
    },
    {
        question: "How do you identify and resolve bottlenecks in a distributed system?",
        answer: "Use distributed tracing (Jaeger/Zipkin) to identify slow spans, analyze metrics for resource saturation, implement SLI/SLO monitoring, use load testing to reproduce issues, profile applications during load, check for lock contention, analyze network latency between services, and review database query performance."
    },
    {
        question: "Design a monitoring system for 1000+ servers",
        answer: `Architecture:
- **Metrics**: Prometheus with federation for scale, Thanos for long-term storage
- **Logs**: Fluentd/Filebeat → Kafka → Elasticsearch
- **Traces**: OpenTelemetry → Jaeger
- **Alerting**: AlertManager with deduplication
- **Dashboards**: Grafana with templated dashboards

Key considerations: Use service discovery for automatic target detection, implement proper cardinality controls, use recording rules for efficiency, design for failure with HA components, and implement RBAC for access control.`
    },
    {
        question: "Design a global file synchronization service",
        answer: `Components:
- Chunking system for efficient transfers
- Content-addressed storage (deduplication)
- Conflict resolution (last-write-wins or version vectors)
- Regional clusters with eventual consistency
- Change detection using filesystem watchers
- Binary diff algorithms for bandwidth efficiency

Considerations: CAP theorem (choose AP for availability), implement merkle trees for efficient sync, use CDC for real-time updates, handle offline scenarios gracefully, and implement end-to-end encryption.`
    },
    {
        question: "Tell me about a time you had to push back on a request from leadership",
        answer: "At my previous role, leadership wanted to skip load testing for a critical release to meet a deadline. I presented data showing our last production incident cost $50K/hour and that load testing would only delay us by 2 days. I proposed a compromise: parallel load testing while preparing rollback procedures. We found and fixed a connection pooling issue that would have caused an outage. Leadership appreciated the data-driven approach and made load testing mandatory going forward."
    },
    {
        question: "How do you balance technical debt with feature delivery?",
        answer: "I make technical debt visible by quantifying its impact - 'this adds 2 hours to every deployment' or 'causes 3 incidents per month.' I advocate for the 80/20 rule: 80% features, 20% debt reduction. I bundle debt fixes with related features when possible and create 'engineering excellence' OKRs that leadership tracks. Most importantly, I frame debt reduction in business terms: reliability, velocity, and cost."
    },
    {
        question: "Describe a complex problem you solved with an elegant solution",
        answer: "We had a service that needed to process millions of events but was hitting memory limits. Instead of scaling vertically, I implemented a streaming architecture using generators in Python, reducing memory usage by 95%. The solution was 50 lines of code that replaced 500 lines of batch processing logic. It was more maintainable, testable, and actually faster due to better cache utilization."
    },
    {
        question: "How do you stay current with technology?",
        answer: "I follow a structured approach: read HackerNews and Reddit's r/sre daily for trends, maintain a home lab for hands-on experimentation, contribute to open source projects, attend virtual conferences (SREcon, KubeCon), participate in our internal tech talks, and read one technical book per month. I also write blog posts to solidify my learning."
    }
];