## What is Serverless?

### How we got there?
On premise(self-hosted) systems -> IaaS -> PaaS -> CaaS(containers) -> FaaS.

There are also BaaS - backend-as-a-service(think of Firebase) which kind of specific SaaSes.

**Serverless** = FaaS + BaaS(or SaaS).
* It is a paradigm of building applications.
* Servers could be still involved.
* You don't manage the underlying layers(below you code).
* Pricing is based on what you consume(time, memory).
* Scaling is flexible.

### Rules of Serverless
* Functions are stateless and run on ephemeral compute services.
* Frontends can be thicker.
* Functions adhere Single Responsibility Principle and written in an event-driven style.
* Utilise third-party vendors to complete functional parts of your application.

## Serverless pros and cons

### Pros
* It's serverless(no servers)
* Versatile(can fix e-commerce or gaming)
* Scaleable(function can scale up to 1000x)
* Manageable migration(only part of your app can be serverless)
* Low cost(don't pay when you don't need the computing power)
* Less code(less layers in backend, frontend can talk to services directly)

### Cons
* Public cloud(don't run mission critical stuff on a public cloud).
* Reliance on SLA. Some services are better than others.
* Limited customization(memory, CPU. Cannot preinstall some stuff).
* Vendor lock-in(to AWS, Azure).
* Decentralized challenges(hard to log analyze data from lots of functions -> inscreased complexity of the system).

## Serverless Principles
1. Use a compute service to execute code on demand
1. Write single-purpose stateless functions
1. Design push-based, event-driven pipelines
1. Create thicker, more powerful front ends
1. Embrace third party services
