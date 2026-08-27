/**
 * Context for the actor-propagation fragments on `docs/auth/fga.mdx`.
 *
 * That section explains how a system actor reaches the agent and tool calls a
 * workflow step makes. The interesting part is the `actor` option, not the
 * workflow around it, so the page shows the call and leaves the workflow to the
 * reader. These stand-ins are that workflow.
 *
 * The type arguments are not decoration. `Workflow` threads the previous step's
 * output type into `then`, so a stand-in left fully generic would reject an
 * agent step for a reason that has nothing to do with the `actor` option the
 * page is documenting. Naming the shape an agent step consumes keeps the check
 * pointed at `actor`.
 *
 * Types are written as inline `import(...)` so a documented block importing the
 * same name does not collide with this file.
 */

/** Stands in for a workflow the reader already built. */
export declare const workflow: import('@mastra/core/workflows').Workflow<
  import('@mastra/core/workflows').DefaultEngineType,
  import('@mastra/core/workflows').Step[],
  string,
  unknown,
  unknown,
  unknown,
  { prompt: string }
>

/** Stands in for a run of that workflow. */
export declare const run: Awaited<ReturnType<(typeof workflow)['createRun']>>

/** Stands in for agents the reader already registered. */
export declare const reportAgent: import('@mastra/core/agent').Agent
export declare const summaryAgent: import('@mastra/core/agent').Agent
