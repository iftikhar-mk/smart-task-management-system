# Azure Key Vault Setup

## To Be Implemented

- Store secrets like `JwtKey`, `DbConnection`, etc.
- Connect using DefaultAzureCredential
- Source secrets securely using `SecretClient`

> Vault Name: SmartTaskVault (expected)
> Secret Naming Convention: Clear & service-scoped

Example:
- AuthService → JwtKey, IdentitySalt
- TaskService → TaskDbConnection
