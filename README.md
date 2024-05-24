# Model

Reusing data types, domain model or `Shared Kernel` in DDD parlance.
This uses Protobuf definitions and holds the equivalent code for both
Golang and Typescript that can be used in userland code.

## Protobuf

If you don’t have buf installed, follow the installation guide from [buf.build](https://buf.build/).

### Generating models

```sh
buf generate
```

### Updating the model

All models are currently defined in the `asset.proto` file. It is a relatively
small model.

> If adding lots of models, might make sense to split into a new file.

The below steps are needed to successfully update and distribute the models:

- Add model changes to `.proto` file.
- Verify there are no errors by linting. Use `buf lint`
- Also format the proto files using `buf format -w`.
- Generate the code definition of your model. Use `buf generate`
- If adding support for a new language, please update `buf.gen.yaml`
to include the task.
- Commit the generated code.
- Bump up the version number in `package.json`

### Reproducible models

On every PR and Push, Github actions runs multiple tasks, one of which runs
`buf generate` on the CI runner and checks if there is a diff between the generated
code you are submitting and what it generates. If there is a diff, the CI run fails.

This ensures bad code isn't mistakenly committed and we can safely distribute the changes to
everyone

## Test

For the test run the following command:

```sh
go test ./...

```
