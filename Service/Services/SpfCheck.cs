using DnsClient;

namespace Service.Services
{
    public class SpfCheck
    {
        static LookupClient dns = new LookupClient();
        public async Task<bool?> CheckSPFAsync(string? domain)
        {
            int score = 0;
            var txtRecords = (await dns.QueryAsync(domain, QueryType.TXT)).Answers.TxtRecords();
            var spfRecord = txtRecords.FirstOrDefault(r => r.Text.Any(t => t.StartsWith("v=spf1")));
            var deprecatedSPF = (await dns.QueryAsync(domain, (QueryType)99)).Answers;

            if (deprecatedSPF.Count == 0)
            {
                score += 1;
            }

            if (spfRecord != null)
            {
                string record = string.Join("", spfRecord.Text);
                score += 1;

                if (record.Split("v=spf1").Length - 1 <= 1)
                {
                    score += 1;
                }

                string[] mechanisms = record.Split(' ');

                string allMechanism = mechanisms.LastOrDefault(m => m.EndsWith("all"));
                if (allMechanism != null)
                {
                    if (record.Trim().EndsWith(allMechanism))
                    {
                        if (allMechanism.StartsWith("+"))
                            score += 2;
                        else if (allMechanism.StartsWith("~"))
                        {
                            score += 1;
                        }
                        else if (allMechanism.StartsWith("?"))
                        {
                            score += 1;
                        }
                    }
                }

                int lookupCount = record.Split(new[] { "include:", "a", "mx", "ptr" }, StringSplitOptions.None).Length - 1;
                if (lookupCount < 10)
                {
                    score += 1;
                }

                if (!record.Contains("ptr"))
                {
                    score += 1;
                }

                score += 1;
            }
            var result = false;
            if (score >= 5)
            {
                result = true;
            }
            return result;
        }
    }
}
