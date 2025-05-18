using DnsClient;

namespace Service.Services
{
    public class DmarckCkeck
    {
        private static readonly LookupClient dnsClient = new LookupClient(new LookupClientOptions
        {
            Timeout = TimeSpan.FromSeconds(2),
            Retries = 1
        });

        private static async Task<int> EvaluateDmarcPolicyScore(string domain)
        {
            string dmarcDomain = $"_dmarc.{domain}";
            try
            {
                var lookup = new LookupClient();
                var result = await lookup.QueryAsync(dmarcDomain, QueryType.TXT);

                var txtRecords = result.Answers.TxtRecords();
                if (!txtRecords.Any())
                    return 0;
                foreach (var txt in txtRecords)
                {
                    string record = string.Join("", txt.Text);
                    if (record.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
                    {
                        var pIndex = record.IndexOf("p=", StringComparison.OrdinalIgnoreCase);
                        if (pIndex == -1)
                        {
                            return 5;
                        }

                        string policy = record.Substring(pIndex + 2).Split(new[] { ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)[0].ToLower();

                        return policy switch
                        {
                            "none" => 5,
                            "quarantine" => 7,
                            "reject" => 10,
                            _ => 5
                        };
                    }
                }

                return 0;
            }
            catch
            {
                return 0;
            }
        }

        public async Task<bool?> HasValidDmarcPolicy(string domain)
        {
            int score = await EvaluateDmarcPolicyScore(domain);
            return score >= 5;
        }
    }
}
