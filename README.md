# pkcs11-tester

.NET 10 development client for PKCS #11 implementations through Pkcs11Interop.
The program inspects module and slot metadata and exercises authentication,
object creation and cryptographic operations.

Build with a .NET 10 SDK:

```sh
dotnet restore pkcs11-tester.sln
dotnet build pkcs11-tester.sln --configuration Release --no-restore
```

CI builds on Linux, macOS and Windows; it does not execute token workflows.
The module path, login credentials and test selection are configured in
`Program.cs`. The default entry point loads `yubihsm_pkcs11` from
`/usr/local/lib/pkcs11/`, with an operating-system-specific library extension,
and creates persistent objects. Review and adapt that configuration for a
disposable test token before running the client. Command-line arguments do not
provide module or credential selection.
