using DnsClient;

using System.Net.Sockets;

using System.Text;

namespace Service.Services
{
    public class MXRecordChecker

    {

        public async Task<List<string>> GetMXRecordsAsync(string domain)

        {

            Dictionary<int, string> mxRecords = new();

            List<string> sortedMxRecords = new List<string>();

            try

            {

                LookupClient client = new LookupClient();

                var queryResult = await client.QueryAsync(domain, QueryType.MX);

                foreach (var record in queryResult.Answers.MxRecords())

                {

                    mxRecords[record.Preference] = record.Exchange.Value;

                }

                if (mxRecords.Count == 0)

                {

                    string[] parts = domain.Split('.');

                    if (parts.Length > 2)

                    {

                        string parentDomain = string.Join(".", parts[^2], parts[^1]);

                        queryResult = await client.QueryAsync(parentDomain, QueryType.MX);

                        foreach (var record in queryResult.Answers.MxRecords())

                        {

                            mxRecords[record.Preference] = record.Exchange.Value;

                        }

                    }

                }

            }

            catch (Exception)

            {

                return sortedMxRecords;

            }

            sortedMxRecords = mxRecords.OrderBy(kvp => kvp.Key).Select(kvp => kvp.Value).ToList();

            return sortedMxRecords;

        }

        public async Task<bool> HasMXRecords(List<string> mxRecords)

        {

            
            if (mxRecords.Count == 0)

            {

                return false;

            }

            return true;

        }

        public string GetParentDomain(List<string> mxRecords)

        {

            var mxRecord = mxRecords?.FirstOrDefault();

            if (string.IsNullOrWhiteSpace(mxRecord))

                return null;

            var host = mxRecord.TrimEnd('.').ToLower();

            var parts = host.Split('.');

            if (parts.Length < 2)

                return null;

            return $"{parts[^2]}.{parts[^1]}";

        }

    }
}
