# Resources Cloud Demo

Spring Cloud demo containing inner resource servers join Gateway server with security Oauth.

Using Spring Boot 1.5 Spring Cloud Edgware.SR6

## Resource1 Server

Simple server having '/api/all/hello' GET endpoint that requests message from Resource2 Server using Spring Feign.

## Resource2 Server

Simple server having '/api/hello' GET endpoint.

## Oauth Server

Basic Spring oauth server with in memory users and clients configurations.

## Gateway Server

Basic Spring Zuul server routing the other servers and configuring oauth security with @EnableResourceServer where '/*/api/**' pattern endpoints require authentication.

## Copyright

Released under the Apache License 2.0. See the [LICENSE](http://www.apache.org/licenses/LICENSE-2.0) file.