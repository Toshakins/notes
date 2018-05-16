## Application Services

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
* Apply on all levels
* Enable traceability
* Automate response to security events
* Focus on your securing your system
* Automate security best practices(like validated AMIs)

#### Definition
Security in the cloud consists of four areas:
* __Data protection__. Classify data availability(public or partially restricted). Implement least privilege access to system. Encrypt evetything where possible(i.e. at rest and in transit). 
* __Privilege management__. Ensures that only authorized and authenticated users are able to access your resources. It can include:
  * ACL
  * Role-based Access Controls
  * Password Management
* __Infrastructure protection__. Outside of the cloud includes things like CCTV, perimeter guards, locks. Inside cloud protection exists on a VPC level.
* __Detective controls__
  * CloudTrail
  * CloudWatch
  * AWS Config
  * S3, Glacier