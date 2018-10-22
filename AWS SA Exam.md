- [Application Services](#application-services)
  * [S3](#s3)
  * [EC2](#ec2)
    + [Storages](#storages)
  * [SQS](#sqs)
  * [SWF(Simple WorkFlow)](#swf-simple-workflow-)
  * [SNS](#sns)
  * [Kinesis](#kinesis)
  * [VPC](#vpc)
- [Pillars](#pillars)
  * [Security](#security)
    + [Design principles](#design-principles)
    + [Definition](#definition)
  * [Reliability](#reliability)
    + [Design principles](#design-principles-1)
    + [Definition](#definition-1)
  * [Cost Optimization](#cost-optimization)
    + [Design Principles](#design-principles)
    + [Definition](#definition-2)
  * [Performance Efficiency](#performance-efficiency)
    + [Design Priciples](#design-priciples)
    + [Definition](#definition-3)
  * [Operational Excelence](#operational-excelence)
    + [Design Principles](#design-principles-1)
    + [Definition](#definition-4)
- [VPC Peering](#vpc-peering)
- [Direct Connect](#direct-connect)
- [Security Token Service](#security-token-service)
  * [Understanding Key Terms](#understanding-key-terms)


## Application Services

### S3
Access control levels:
* IAM
* Bucket policy
* ACL(restrict access to the group of AWS users)
* Query String Auth(via HTTP paremeters).

Encryption options:
* __SSE-S3__. Amazon handles key management and key protection.
* __SSE-C__. AWS user controls keys used to encrypt objects.
* __SSE-KMS__. Encryption keys managed with AWS KMS. KMS provides a trail to monitor who used a key, when and for what.

Storage options
* Standard
* IA(infrequent access)
* IA one-zone
* Reduced Redundancy. AWS does not recommend to use it as Standard is more cost-effective.
* Glacier

S3 Select is a new functionality that allows "querying in place", i.e. getting parts of the stored objects.

S3 Inventory provides audit and reports on objects state. Contrary to the LIST request Inventory is a scheduled job and can be applied to a subset of a bucket's objects(and return more data). Reports stored in CSV or ORC at specific destination.

Lifecycle management. It helps to build you an flow for objects between different storage options, e.g. transit Standard -> IA -> Glacier. Lifecycle gotcha: you can expire and delete unfinished multipart uploads.

### EC2
Pricing models:
* On demand
* Reserved capacity
* Spot
* Dedicated hosts

Instance types:
**FIGHT DR MC PIX**
* General Purpose
  * T. Burstable.
  * M. Fixed performance without burst.
* Compute Optimized
  * C
* Memory Optimized
  * R
  * X1(e). SAP-certified instance type for huge databases.
  * U. High-memory instances(several TiB).
  * Z1d. Recommended for electronic design automation and certain relational database workloads with high per-core licensing costs.
* Storage Optimized
  * H. HDD storage with high-speed networking. MapReduce, NFS, log processing.
  * I. NVMe-backed instances for hight random IO and hight sequential read. Bare metal instances included.
  * D. Massive-size HDD storage. Even bigger MapReduce, warehouses.
  
* Accelerated Computing
  * P. General purpose GPU instances.
  * G. Graphics-intensive applications.
  * F. FPGA hardware acceleration.

SSD:
* General Purpose SSD
* Provisioned IOPS

Magnetic:
* Throughput Optimized
* Cold HDD
* Magnetic(previous generation)

Security Groups are **STATEFUL**(allowed traffic allows in and out). You can specify only ALLOW rules.

Snapshots of encrypted volumes are encrypted automatically. You can share only unencrypted snapshots.

#### Optimize CPU
You can [disable Hyper-Threading](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-optimize-cpu.html) for intensive workloads.

#### Storages
* EBS Volumes
* Instance store - ephemeral

#### EC2 Fleet
EC2 fleet is a feature to start a fleet of instances with a one API call.

### SQS
Worth reading an FAQ. Message queue, works with in a "poll" model. Messages 256 KB size and can be queued from 1 min to 14 days.

SQS has a visibility timeout that makes message invisible between moments when reader reads and deletes the message. If
message is not processed in that timeout, it will reappear and will be available for pulling again(redelivery). Max timeout 
is 12 hours.

SQS guarantees that messages will be processed at least once.

Long polling does not return response until message arrives in the queue or request times out. Long polling more cost-effective
than short-polling.

Queue can be standard or FIFO.

### SWF(Simple WorkFlow)

Workflow retention up to 1 year. Presents task-oriented API and can include real-life work. Guarantees that task assigned once
and never duplicates. SWF tracks all tasks and events in application(SQS needs application-level tracking).

SWF Actors:
* Workflow Starter(e-commerce app when order is placed)
* Deciders(controls the flow of activity in the task. If something has finished or failed, deciders decide what is next)
* Carry out workers(does the work)

Shorts:
* Domain is a collection of related workflows

### SNS
Notification service with a "push" model. Can push messages to HTTP(S), Email, SQS, Application, Lambda.

### Kinesis
Consists of:
* Kinesis Streams. Consists of the shards which deliver messages to consumers(EC2). Retention: 24h - 7d.
* Kinesis Firehose. Allows optional processing with Lambda. If not present, stores data in S3.
* Kinesis Analytics

### VPC

* [VPC with private and public subnet](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html)


## Pillars

### Security

#### Design principles
* Apply on all levels
* Enable traceability
* Automate response to security events
* Focus on your securing your system
* Automate security best practices(like validated AMIs)

#### Definition
Security in the cloud consists of four areas:
* __Data protection__. Classify data availability(public or partially restricted). Implement least privilege access to system. Encrypt evetything where possible(i.e. at rest and in transit). 
  * How do you protecting your data at rest?
  * How do you protecting your data in transit?
* __Privilege management__. Ensures that only authorized and authenticated users are able to access your resources. It can include:
  * ACL
  * Role-based Access Controls
  * Password Management
  
  Questions:
  * How do you protect access to and use of AWS root account credentials?
  * How are defining roles and responsibilites of system users to control human access to AWS Management Console and APIs?
  * How are you limiting automated access(i.e. access from applications)?
* __Infrastructure protection__. Outside of the cloud includes things like CCTV, perimeter guards, locks. Inside cloud protection exists on a VPC level.
  * How are you enforing network and host-boundary protection?
  * How are you enforcing AWS service level protection?
  * How are protecting the integrity of operation systems?
* __Detective controls__. How are you analyzing logs?
  * CloudTrail
  * CloudWatch
  * AWS Config
  * S3, Glacier

### Reliability
Covers the ability of your system to recover from service or infrastructure outages as well as ability to dynamically acquire computing resources to meet demand.

#### Design principles
* Test recovery procedures(chaos monkey)
* Automatically recover from failures
* Scale horizontally
* Stop guessing capacity
* Manage change in automation

#### Definition
##### __Foundation__. 
* Limit Management. Ensure you track your AWS limits for services. Those are enforced by region and account.
* Networking. Ensure you specify IP addresses that will last across several availability zones. Have duplicated means communicating with and withing your cloud. Leave unused CIDR space within VPC. Protect yourself against DoS attacks on the network level(AWS Shield + WAF).

##### __Application Design for High Availability__
* Understand availability needs. Not every system needs five nines of resilience.
* Design itself
  * Fault Isolation Zones. Extra note: __shuffle sharding__.
  * Redundant Components
  * Micro-service architecture. Drawbacks: Distribution, eventual consistency, operational complexity. Positives: strong module boundaries, independent deployment, technology diversity. 
  * Recovery-oriented computing. Many different types of failure can be recovered with one path. Develop for recovery and test for recovery.
  * Distributed systems best practices
    * Throttling
    * Exponential back-off
    * Fail fast. Do not queue errors. Release resources ASAP.
    * Use of idempotency tokens
    * Constant work. If you know your exact capacity of slots for workload, make sure you always put something into those slots to avoid performance spikes. Possible to put a "filler" work([idk AWS talking about](https://aws.amazon.com/blogs/architecture/doing-constant-work-to-avoid-failures/)).
    * Circuit breaker
    * Bi-modal behavior and static stability. Avoid negative feedback loops in system design. Failure in one component should not affect responsiveness in another one.
* Operational Considerations
  * Automate deployments to eliminate impact(canary, blue-green, feature toggles).
  * Testing
  * Monitoring and Alarming(percentile monitoring based on max characteristics. Do not use averages).
  * Operational Readiness Review. Could be performed twice a year.
  * Auditing
### Cost Optimization

#### Design Principles

* Transparently attribute expenditure(tag AWS resources per unit, department etc.)
* Use managed service to reduce ownership
* Trade capital expense for operating expense(utilise resources when needed, not constantly)
* Benefit from economies of scale
* Stop spending money on data center operations

#### Definition
* Matched supply and demand. Do not over(or under) provision, be agile.
  * How do you make sure that you capacity matches but does not substantially exceed what you need?
  * How are you optimizing your usage of AWS services
* Cost-effective resources. e.g. pick right instance to do the job.
  * Have you selected the appropriate resource type?
  * Have you selected the appropriate pricing model?
  * Are there managed services that can improve your ROI?
* Expenditure awareness. Be aware who runs what resources. Use cost allocation tags, billing alerts and consolidated billing.
  * What means do you have to control AWS costs?
  * How are you monitoring usage and spending?
  * How do you decomission resources that no longer need?
  * How do you consider data-transfer charges when designing your architecture?
* Optimizing over time. AWS moves rapidly. Go together with Amazon and use the best newest services. Subscribe to the blog! Use Trusted Advisor!
  * How do you manage and consider adoption of new services?

### Performance Efficiency

#### Design Principles

* Democratize advanced technologies(easier adoption of techonologies like SageMaker, DynamoDB).
* Go global in minutes
* Use server-less architectures
* Experiment more often

#### Definition

* Compute
  * How do you select the appropriate instance type for your system?
  * How do you ensure that you have most appropriate features and instance type when new features are introduced?
  * How do you monitor instances post-launch to ensure they behave as expected?
  * How do you ensure that quantity of your instances matches the demand?
* Storage
  * How do you select the appropriate storage solution for your system?
  * How do you ensure that you have the most appropriate storage solution when new features are launched?
  * How do you monitor your storage to ensure that it behaves as expected?
  * How do you ensure that capacity and throughput of your storage solution matches the demand?
* Database
  * How do you select the appropriate database solution?
  * How do you ensure that database behaves correctly?
  * How do you monitor databases to ensure that it behaves correctly?
  * How do you assure you have right capacity and throughput?
* Space-time tradeoff. Services: Elasticase, CloudFron, DirectConnect.
  * How do you select the appropriate proximity and caching solutions for your system?
  * How do you ensure those solutions are updated as new feature are coming in?
  * The same.
  * The same.

### Operational Excelence

Includes operational practices and procedures used to manage production workloads. This includes how planned changes are executed, as well as response to unexpected operational events. Change execution and responses should be automated. All procedures and processes of operational excellence should be documented, tested and regularly reviewed.

#### Design Principles
* Perform operations with code
* Align operations processes to business objectives
* Make regular, small, incremental changes
* Test for responses to unexpected events
* Learn from operational events and failures
* Keep operations procedures current(up-to-date)

#### Definition
* Preparation. Operation checklists will ensure that workload is ready for production, and prevent unintentional production promotion without effective preparation. Workloads should have;
  * Runbooks - operations guidance that operations teams can refer to so they can perform normal daily tasks.
  * Playbooks - guidance for responding to unexpected operational events. Should include response plans, as well as escalation paths and stakeholder notifications.
  Services: CloudFormation, AutoScaling, AWS Config, tagging.
  Questions:
  * What best practices for cloud operation are you using?
  * How are you doing configuration management for your workload?
* Operations. Should be focused on automation, small frequent changes, reqular QA testing, and defined mechanism to track, audit, roll back, and review changes. Changes should not require scheduled downtime and they should not require manual execution. A wide range of logs and metrics that based on key operational indicators for a workload should be collected and reviewed to ensure continuous operations. Services: PipeLine, CodeCommit, CodeDeploy, CloudTrail.
  * How you are evelving your workload while minimizing the impact of change?
  * How do you monitor your workload to ensure it is operating as expected?
* Responses. Should cover alerts, mitigation, remediation, rollback and recovery. Alerts should be timely and escalate when no adequate mitigation happened. QA mechanisms should be set in place to roll back failed deployments. Responses should follow a pre-defined playbook that includes the stakeolders, the escalation process and procedures. Escalation path should be defined and include both functional and hierarchical escalation capabilities. Hierarchical escalation should be automated, and escalated priority should result in a stakeholder notification. __Services__: SNS, CloudWatch..
  * How do you respond to unplanned operational events?
  * How is escalation managed when responding to unplannedoperational events?

## VPC Peering

It is simply a connection between two VPCs that enable you to route traffic using private IP addresses. Additionally, it is possible to create VPC endpoints for services such as S3(so access won't be publicly visible).

## Direct Connect

AWS DC makes it easy to establish a dedicated network connection from your premises to AWS. In many cases it can reduce network costs, increase bandwidth and provide more consistent network experience than Internet-based connections.

Premises connect to a DC facility which has a high-speed connection to AWS datacenters.

## Security Token Service

Grants users limited and temporary access to AWS resources. Users can come from three sources:

* Federation(e.g. Active Directory).
  * Uses SAML
  * Grants temporary access based on credentials
  * Does need to be a user in IAM
  * SSO allows users to log in without assigning AWS credentials
* Federation with mobile apps
  * Uses FB/Amzn/Google/OpenID providers to log in
* Cross Account Access
  * Let's users from one AWS account to another

### Understanding Key Terms

* __Federation__: combining or joining a list of users in one domain(such as IAM) with a list of users in another domain(such as AD, FB and etc.)
* __Identity Broker__: a service that allows you to take an identity from point A and join it(federate it) to point B.
 
