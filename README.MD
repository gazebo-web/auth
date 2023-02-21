# Auth

Auth is a gRPC service implementation of the fine-grained [Authorization API](github.com/OpenSourceRobotics/api).

It is capable of defining users and organizations, and handling authorization for them. The specific authorization 
scheme can be configured through the selection of modular authentication backends.

This service does not handle authentication. It assumes that all requests reaching it are coming from trusted sources
and does not perform any validation. It is meant for deployment in a private environment.

## Setup

The application is currently configured through the use of environment variables. The `.env.example` file provides 
an example file with all configuration options with sensible defaults. It is recommended to make a copy and edit that 
file to configure the service.

### Authorization Backends

Authorization is enforced using authorization backend implementations, which allow interfacing with different 
authorization systems.

All backend implementations guarantee the same behavior through the implementation of an authorization interface.

The authorization backend is selected from a fixed set of options with the `AUTH_BACKEND` environment variable. Note 
that each authorization backend might require additional configuration options specific to the implementation. For 
information on backend configuration values, refer to their documentation.
