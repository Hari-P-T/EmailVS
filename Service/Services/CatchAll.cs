using System.Net.Sockets;
using System.Text;

namespace Service.Services
{
    public class CatchAll
    {
        public async Task<bool?> IsCatchAllAsync(string domain, string mxHost)
        {
            string testAddress = $"nonexistent{Guid.NewGuid():N}@{domain}";

            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(mxHost, 25);
                using var stream = client.GetStream();

                async Task<string> GetResponseAsync()
                {
                    var buffer = new byte[1024];
                    int bytes = await stream.ReadAsync(buffer);
                    return Encoding.ASCII.GetString(buffer, 0, bytes);
                }

                async Task SendAsync(string command)
                {
                    var data = Encoding.ASCII.GetBytes(command);
                    await stream.WriteAsync(data, 0, data.Length);
                }
                await SendAsync($"RCPT TO:<{testAddress}>\r\n");
                var rcptResponse = await GetResponseAsync();
                await SendAsync("QUIT\r\n");

                var code = rcptResponse.Substring(0, 3);
                return code == "250" || code == "251" || code == "252";
            }
            catch
            {
                return null;
            }
        }
    }
}
