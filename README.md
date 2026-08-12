# Security Docs — Top 25 Stacks

A defensive reference library: one detailed markdown file per technology stack, each covering misconfigurations that can leak filesystem/source/data and the stack's common vulnerabilities. Every file follows the same structure: what it is, dangerous pattern, what leaks, fix, detection grep, and a checklist.

These are defensive references for hardening systems you own. Do not use the patterns to attack systems you do not own.

## Backend frameworks

1. [Node.js + Express](./01-nodejs-express.md)
2. [NestJS](./02-nestjs.md)
3. [Python + Django](./03-django.md)
4. [Python + Flask](./04-flask.md)
5. [Python + FastAPI](./05-fastapi.md)
6. [Java + Spring Boot](./06-spring-boot.md)
7. [Java + Spring Security](./07-spring-security.md)
8. [PHP + Laravel](./08-laravel.md)
9. [PHP (raw / PDO)](./09-php-raw.md)
10. [Ruby on Rails](./10-rails.md)
11. [Go (net/http, Gin, Echo)](./11-go.md)
12. [Rust (Actix, Axum)](./12-rust.md)
13. [C# / ASP.NET Core](./13-aspnet-core.md)

## API / RPC

14. [GraphQL (Apollo, Hasura)](./14-graphql.md)
15. [gRPC](./15-grpc.md)

## Frontend / full-stack

16. [Next.js](./16-nextjs.md)
17. [React (SPA)](./17-react-spa.md)
18. [Angular](./18-angular.md)
19. [Vue.js / Nuxt](./19-vue-nuxt.md)

## Infrastructure / data

20. [Docker](./20-docker.md)
21. [Kubernetes](./21-kubernetes.md)
22. [Nginx](./22-nginx.md)
23. [Redis](./23-redis.md)
24. [PostgreSQL](./24-postgresql.md)
25. [MongoDB](./25-mongodb.md)

## Vibe-coded (AI-generated) applications

26. [Vibe-coded — Overview](./26-vibe-coded-overview.md)
27. [Vibe-coded — Secrets & supply chain](./27-vibe-coded-secrets-supplychain.md)
28. [Vibe-coded — Authentication & authorization](./28-vibe-coded-auth-authz.md)
29. [Vibe-coded — Injection & input validation](./29-vibe-coded-injection-validation.md)
30. [Vibe-coded — Configuration & deployment](./30-vibe-coded-config-deployment.md)

## How to use

- Pick the stack(s) matching your service.
- Run the detection greps in your repo.
- Work through the checklist per file.
- Cross-cutting concerns (secrets in git, logging, headers) repeat across files on purpose — they apply everywhere.
