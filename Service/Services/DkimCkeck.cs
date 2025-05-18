using DnsClient;

namespace Service.Services
{
    public class DkimCkeck
    {
        static LookupClient dnsClient = new LookupClient();

        public async Task<bool?> HasAnyDkimRecord(string domain)
        {
            var selectors = new List<string>
    {
        "default", "selector1", "selector2", "google", "20230601",
        "mail", "6ujb3doj4mwbngmp2xjutilwl4zbdio3", "s1", "s2",
        "smtp", "dkim", "mg", "mandrill", "mta", "zmail", "zoho",
        "1522905413783", "pm", "k1", "key1", "key2", "sendgrid",
        "amazonses", "eaxkvsyelrnxjh4cicqyjjmtjpetuwjx", "br"
    };

            var tasks = selectors.Select(async selector =>
            {
                string dkimDomain = $"{selector}._domainkey.{domain}";
                try
                {
                    var result = await dnsClient.QueryAsync(dkimDomain, QueryType.TXT);
                    var txtRecord = result.Answers.TxtRecords().FirstOrDefault();
                    if (txtRecord != null)
                    {
                        string recordValue = string.Join("", txtRecord.Text);
                        if (recordValue.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
                catch
                {
                    // Ignore exceptions for non-existent records
                }
                return false;
            });

            var results = await Task.WhenAll(tasks);
            return results.Any(r => r);
        }
    }
}
