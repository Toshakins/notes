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
