using EmailAddressVerificationAPI.Models;
using Microsoft.Extensions.Caching.Memory;

namespace EmailAddressVerificationAPI.Services
{
    public class GreyListedDomainsCheck
    {
        private readonly IMemoryCache _cache;
        private const string CacheKey = "GreyListedDomains";
        private const string FilePath = "greylistedDomains.txt";

        private static readonly object CacheLock = new();

        public GreyListedDomainsCheck(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
            LoadDomains();
        }

        private void LoadDomains()
        {
            try
            {
                var topLevelDomains = new HashSet<string>();

                if (File.Exists(FilePath))
                {
                    foreach (var line in File.ReadLines(FilePath))
                    {
                        var domain = line.Trim().ToLower();
                        if (!string.IsNullOrEmpty(domain))
                        {
                            topLevelDomains.Add(domain);
                        }
                    }
                }

                _cache.Set(CacheKey, topLevelDomains, new MemoryCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromDays(60)
                });
            }
            catch (Exception)
            {
                throw;
            }
        }

        public async Task<bool?> IsGreyListedDomain(string domain)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(domain))
                {
                    return false;
                }

                if (!_cache.TryGetValue(CacheKey, out HashSet<string>? disposableDomains))
                {
                    lock (CacheLock)
                    {
                        if (!_cache.TryGetValue(CacheKey, out disposableDomains))
                        {
                            LoadDomains();
                            _cache.TryGetValue(CacheKey, out disposableDomains);
                        }
                    }
                }


                if (disposableDomains.Contains(domain.ToLower()))
                {
                    return false;
                }

                return true;
            }
            catch (Exception)
            {
                return null;
            }
        }

    }
}