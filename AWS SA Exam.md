## Application Services

### S3
__Access control levels__:
* IAM
* Bucket policy
* ACL(restrict access to the group of AWS users)
* Query String Auth(via HTTP paremeters).

__Encryption options__:
* __SSE-S3__. Amazon handles key management and key protection.
* __SSE-C__. AWS user controls keys used to encrypt objects.
* __SSE-KMS__. Encryption keys managed with AWS KMS. KMS provides a trail to monitor who used a key, when and for what.

__Storage options__
* Standard
* IA
* IA one zone
* Reduced Redundancy
* Glacier

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

#### Definition
* __Foundation__. AWS almost limitless in terms of providing infrastructure. However, it sets service limits to preserve from overbooking the capabilities. Key services: IAM, VPC.
  * How are you managing service limits?
  * How are you planning your network topology on AWS?
  * Do you have an escalation path to deal with technical issues?
* __Change management__. Monitor any change to the system to be able to react in time. Key services: CloudTrail.
  * How does your system adapt to changes in demand?
  * How are you monitoring the AWS resources?
  * How are you excuting change management?
* __Failure management__. Plan failure, plan reaction to them. Ensure you are aware of the failure. Key services: CloudFormation.
  * How are you backing up your data?
  * How does your system withstand component failures?
  * How are you planning for recovery?
