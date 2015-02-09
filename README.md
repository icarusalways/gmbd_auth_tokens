# Groovy Sling Authentication Handler

This project aims to create a sling AuthenticationHandler that 

* Is completely implemented in Groovy
* Authenticates users into the JCR 
* Creates and stores login-tokens (cookies) in a NoSQL database (mongodb)
* Creates and stores profile information in a NoSQL database
* Optionally Authenticates users with a configured LDAP
* Optionally allows user and group creation based on LDAP entry
* Supports a distributed sling topology

The goals outlined above combine to create a distributed sling environment where a user will stay logged in even if requests are serviced by different sling instances

One way of completing this task would be to cluster the sling instances to use the exact same JCR. This is possible but has not worked well in past experience with Adobe CQ5.

Advantages of this Authentication Handler over clustering sling instances
* Bundle starts working immediately after it is installed
* Ease of configuration
* Avoidance JCR corruption
* Add N number of sling instances without a large impact to perfomance

### Current Features
