

    namespace EmailAddressVerification.Services
    {
        using System;
        using System.IO;
        using System.Net.Sockets;
        using System.Text;
        using DnsClient;
        using System.Linq;
        using System.Threading.Tasks;

     public class EmailValidator
        {
        public enum EmailStatus
        {
            Valid,
            Invalid,
            TempFailure,
            AuthRequired,
            Unknown,
            Error
        }

        public static async Task<(EmailStatus status, string reason)> VerifyEmailAsync(string email)
        {
            var domain = email.Split('@').LastOrDefault();
            if (string.IsNullOrEmpty(domain))
                return (EmailStatus.Invalid, "Invalid email format");

            // Step 1: Get MX record
            var lookup = new LookupClient();
            var result = await lookup.QueryAsync(domain, QueryType.MX);
            var mxRecord = result.Answers.MxRecords().OrderBy(r => r.Preference).FirstOrDefault();

            if (mxRecord == null)
                return (EmailStatus.Invalid, "No MX records found for domain");

            var smtpServer = mxRecord.Exchange.Value;

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(smtpServer, 25);
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                using var writer = new StreamWriter(stream) { AutoFlush = true };

                string ReadLine() => reader.ReadLine();
                void WriteLine(string cmd)
                {
                    writer.WriteLine(cmd);
                    Console.WriteLine(">>> " + cmd);
                }

                string response = ReadLine(); // Server greeting

                WriteLine("HELO verifier.com");
                response = ReadLine();

                WriteLine("MAIL FROM:<test@yourdomain.com>");
                response = ReadLine();
                if (response.StartsWith("530") || response.StartsWith("535") || response.StartsWith("334"))
                    return (EmailStatus.AuthRequired, $"Auth required: {response}");

                // Step 2: Check RCPT TO for actual email
                WriteLine($"RCPT TO:<{email}>");
                string realResponse = ReadLine();

                // Step 3: Check RCPT TO for a known fake email
                string fakeEmail = $"nonexistent_{Guid.NewGuid().ToString("N").Substring(0, 10)}@{domain}";
                WriteLine($"RCPT TO:<{fakeEmail}>");
                string fakeResponse = ReadLine();

                // Step 4: Evaluate responses
                if (realResponse.StartsWith("250"))
                {
                    if (fakeResponse.StartsWith("250"))
                        return (EmailStatus.Unknown, "Catch-all or protected domain — cannot verify individual address");
                    else
                        return (EmailStatus.Valid, "Email address accepted (250)");
                }

                if (realResponse.StartsWith("251"))
                    return (EmailStatus.Valid, "User not local, but will forward");

                if (realResponse.StartsWith("252"))
                    return (EmailStatus.Unknown, "Cannot verify user, but accepting message");

                if (realResponse.StartsWith("354"))
                    return (EmailStatus.Unknown, "Server is ready for message body");

                if (realResponse.StartsWith("4"))
                    return (EmailStatus.TempFailure, $"Temporary error: {realResponse}");

                if (realResponse.StartsWith("5"))
                    return (EmailStatus.Invalid, $"Mailbox not found or blocked: {realResponse}");

                return (EmailStatus.Unknown, $"Unrecognized response: {realResponse}");
            }
            catch (SocketException ex)
            {
                return (EmailStatus.Error, $"Socket error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (EmailStatus.Error, $"Unhandled exception: {ex.Message}");
            }
        }

    }

    }

