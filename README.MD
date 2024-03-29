# Auth

Auth is an open source library for adding authentication and authorization to web services. 
Its objective is to reduce the amount of time needed to set up an auth layer in applications, allowing them to focus on developing new features instead.

*DISCLAIMER*: This library is under active development and may introduce unscheduled breaking changes in the near future.

## Install

```shell
go get github.com/gazebo-web/auth
```

## Providers
This library is designed with a set of generic interfaces for `Authentication` and `Authorization`, we also provide
some integrations for different auth providers.

| Type           | Provider                          |
|----------------|-----------------------------------|
| Authentication | Auth0                             |
| Authentication | Firebase                          |
| Authentication | Google Cloud - Identity Platform* |
| Authorization  | SpiceDB*                          |


`*` To be implemented

## Contribute
There are many ways to contribute to this library

- Reviewing the source code changes.
- Report new bugs.
- Suggest new changes.
