# dtrack

[Dependencytrack](https://dependencytrack.org/) is a tool for scanning dependencies for vulnerabilities.

> [!WARNING]
> This repository is a **hard fork** of the original NAIS repository. The original repository can be found at
> [https://github.com/nais/dependencytrack](https://github.com/nais/dependencytrack).
>
> **Breaking Changes**: This fork modifies the Go module path. We do not maintain compatibility with the upstream repository.

KvalitetsIT maintains this hard fork with customizations for internal use, including helm charts, bootstrap configuration, stateful deployments, and a modified Go module.

## Using the Dependencytrack Client

The repository provides a client for dependencytrack, enabling integrations and custom implementations. To add the client to your project, run:

```bash
go get -u github.com/KvalitetsIT/dtrack@HEAD
```

Feel free to expand the client interface with additional functionality as needed.

## Local Development

### Getting Started

Start a local dependencytrack environment:

```bash
make compose
```

This starts a Docker Compose setup with dependencytrack. Configuration is managed via:
- `.env` - Copy from `.env.sample` and configure with your values
- `users.yaml` - Define pre-installed test users for automated testing

**Access points:**
- [Dependencytrack UI](http://localhost:9000) - Web interface
- [Dependencytrack API](http://localhost:9001) - REST API
- [Swagger UI](http://localhost:9002) - API documentation

### Development Workflow

1. Set up your `.env` file from `.env.sample`
2. Configure test users in `users.yaml` if needed
3. Run `make compose` to start services
4. Make changes to the codebase
5. Services will reload automatically or restart with `make compose`

## License

This project is licensed under the MIT License, see [LICENSE.md](/LICENSE.md). It is derived from [nais/dependencytrack](https://github.com/nais/dependencytrack), also licensed under MIT.
