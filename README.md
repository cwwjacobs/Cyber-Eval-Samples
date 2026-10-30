# Cyber evaluation sample

Sample long-horizon evaluation tasks in the [Harbor](https://github.com/harbor-framework/harbor) task-folder format used by FrontierSWE.

| Task | Kind | What the agent does |
|---|---|---|
| [`cindermote-from-scratch`](cindermote-from-scratch/README.md) | Long-horizon software engineering, security domain | Builds Cindermote, a fail-closed containment runtime for untrusted AI-agent material, from its documentation and test suite, with none of its Python source provided |

Each task folder contains `instruction.md`, `task.toml`, a Docker environment, a verifier that writes a reward, and a reference solution in `solution/solve.sh`:

```bash
harbor run -p cindermote-from-scratch -a oracle
harbor run -p cindermote-from-scratch -a nop
```

The Cindermote material inside the task (`environment/app/` and `solution/reference.patch`) is by Corey Jacobs and licensed under the PolyForm Noncommercial License 1.0.0; see `cindermote-from-scratch/environment/app/LICENSE`.
