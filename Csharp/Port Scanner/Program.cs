using System.Diagnostics;
using System.Net.Sockets;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var host = "127.0.0.1"; // change this line
        var sPort = 0;          // change this line
        var ePort = 65535;      // change this line

        var stopwatch = Stopwatch.StartNew();

        Console.WriteLine($"[!] Scanning target: {host}\n");

        await PortScanner(host, sPort, ePort);

        stopwatch.Stop();
        Console.WriteLine($"\nElapsed Time: {stopwatch.ElapsedMilliseconds}");
    }

    private static async Task PortScanner(string host, int sPort, int ePort) {
        var tasks = new List<Task>();

        for (var port = sPort; port <= ePort; port++)
        {
            tasks.Add(PortScanAsync(host, port));
        }

        await Task.WhenAll(tasks);
    }

    private static async Task PortScanAsync(string host, int port)
    {
        using (var client = new TcpClient())
        {
            var cToken = new CancellationTokenSource(1000);

            try
            {
                await client.ConnectAsync(host, port).WaitAsync(cToken.Token);
                if (client.Connected)
                {
                    Console.WriteLine($"Port {port} is open.");
                }
            } 
            
            catch
            {
                
            }
        }
    }
}
