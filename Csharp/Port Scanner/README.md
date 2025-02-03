# Port Scanner

A simple, multi-threaded TCP port scanner written in C#.

## Prerequisites

- .NET 9.0 or higher
- Visual Studio 2022 or compatible IDE

## Usage

1. Open the `Program.cs` file
2. Modify the following variables as needed:
```csharp
var host = "127.0.0.1"; // Target IP address
var sPort = 0;          // Starting port
var ePort = 65535;      // Ending port
```
3. Run the program:
```bash
dotnet run
```

## Example Output

```
[!] Scanning target: 127.0.0.1

Port 80 is open.
Port 443 is open.
Port 3306 is open.
Port 8080 is open.

Elapsed Time: 1234
```
