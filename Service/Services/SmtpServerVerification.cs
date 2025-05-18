using DnsClient;
using EmailAddressVerification.Services;
using EmailAddressVerificationAPI.Models;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EmailAddressVerificationAPI.Services
{
    public class SmtpValidator

    {

        private async Task<bool?> CheckSingleMXAsync(string email, string domain, string mxRecord)

        {

            int port = 25;

            TcpClient? client = null;

            Stream? stream = null;

            try

            {

                client = new TcpClient();

                await client.ConnectAsync(mxRecord, port);

                stream = client.GetStream();

                string response = await ReceiveResponseAsync(stream);

                string code = response.Substring(0, 3);

                Console.WriteLine($"{code} : For TCP connection");

                if (string.IsNullOrEmpty(response) || !(code == "220"))

                    return null;

                await SendCommandAsync(stream, "HELO verifier.com\r\n");

                response = await ReceiveResponseAsync(stream);

                code = response.Substring(0, 3);

                if (code != "250")

                    return false;

                // MAIL FROM

                await SendCommandAsync(stream, $"MAIL FROM:<test@verifier.com>\r\n");

                response = await ReceiveResponseAsync(stream);

                code = response.Substring(0, 3);

                if (code != "250" && code != "251")

                    return false;

                // RCPT TO

                await SendCommandAsync(stream, $"RCPT TO:<{email}>\r\n");

                response = await ReceiveResponseAsync(stream);

                code = response.Substring(0, 3);

                await SendCommandAsync(stream, "QUIT\r\n");


                if (code == "250" || code == "251" || code == "252" || code == "552")

                    return true;

                if (code == "550" || response.Contains("5.1.1") || response.ToLower().Contains("user unknown"))

                    return false;

                return null;

            }

            catch (Exception)

            {

                return null;

            }

            finally

            {

                stream?.Dispose();

                client?.Close();

            }

        }


        private async Task SendCommandAsync(Stream stream, string command)

        {

            byte[] buffer = Encoding.ASCII.GetBytes(command);

            await stream.WriteAsync(buffer, 0, buffer.Length);

            await stream.FlushAsync();

        }

        private async Task<string> ReceiveResponseAsync(Stream stream)

        {

            byte[] buffer = new byte[1024];

            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

            return Encoding.ASCII.GetString(buffer, 0, bytesRead);

        }


        public async Task<bool> IsSMTPValid(string email, string domain, List<string> mxRecords)

        {

            if (mxRecords.Count > 0)

            {

                foreach (var mxRecord in mxRecords)

                {

                    var result = await CheckSingleMXAsync(email, domain, mxRecord);

                    if (result == true)

                    {

                        return true;

                    }

                    else if (result == false)

                    {

                        return false;

                    }

                    else

                    {

                        continue;

                    }

                }

            }

            return false;

        }


        //catch all method
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