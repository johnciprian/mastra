# MastraCode contributor guide

Use this guide to find the right package and run Factory locally.

## Packages

| Package                                        | Responsibility                                             |
| ---------------------------------------------- | ---------------------------------------------------------- |
| [`factory`](./factory/README.md)               | Factory backend: storage, routes, rules, and integrations  |
| [`factory-auth`](./factory-auth/README.md)     | Auth provider contract, helpers, and the conformance suite |
| [`factory-ui`](./factory-ui/README.md)         | Factory React application and browser tests                |
| [`web`](./web/README.md)                       | Local and deployable Factory host                          |
| [`sdk`](./sdk/README.md)                       | Shared coding-agent runtime                                |
| [`tui`](./tui/README.md)                       | Terminal interface                                         |
| [`mastra-factory`](./mastra-factory/README.md) | `create-factory` scaffolder                                |

`factory-auth` is Apache-2.0 and published as `@mastra/factory-auth`. Work on it when you are writing or adapting an auth provider; you do not need it to use a provider that already works. Its module graph must stay free of enterprise (`ee/`) code, and two checks enforce that. See [the package README](./factory-auth/README.md#the-ee-boundary) before changing what it imports.

## Setup

From the repository root:

```shell
pnpm install
pnpm --dir mastracode/web install
pnpm --dir mastracode/web run prebuild
```

The web host is a separate pnpm project. `prebuild` builds the local packages it links to.

## Run Factory

First complete the [local GitHub App setup](./web/README.md#configure-local-onboarding).

For backend work, run the API and bundled UI together:

```shell
pnpm --dir mastracode/web dev
```

Open `http://localhost:5873`.

For UI work with hot module replacement, run the Docker services, the API, and the Vite dev server together:

```shell
pnpm --dir mastracode/web dev:ui
```

Open `http://localhost:5173`. To run them in separate terminals instead, start the Docker services with `pnpm --dir mastracode/web db:up`, then run `pnpm --dir mastracode/web api` and `pnpm --filter ./mastracode/factory-ui dev`.
