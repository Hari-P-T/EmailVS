using EmailAddressVerificationAPI.Models;
using Microsoft.Extensions.Caching.Memory;

namespace EmailAddressVerificationAPI.Services
{
    public class DisposableDomainsCheck
    {
        private readonly IMemoryCache _cache;
        private const string CacheKey = "DisposableDomains";
        private const string FilePath = "disposableDomains.txt";

        private static readonly object CacheLock = new();

        public DisposableDomainsCheck(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
            LoadDisposableDomains();
        }

        private void LoadDisposableDomains()
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

        public async Task<bool?> IsDisposableDomain(string domain)
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
                            LoadDisposableDomains();
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