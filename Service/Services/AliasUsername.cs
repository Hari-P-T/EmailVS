using EmailAddressVerificationAPI.Models;
using Microsoft.Extensions.Caching.Memory;

namespace EmailAddressVerificationAPI.Services
{
    public class AliasUsernameCheck
    {
        private readonly IMemoryCache _cache;
        private const string CacheKey = "Alias";
        private const string FilePath = "AliasNames.txt";

        private static readonly object CacheLock = new();

        public AliasUsernameCheck(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
            LoadFile();
        }

        private void LoadFile()
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

        public async Task<bool?> IsAliasUsername(string domain)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(domain))
                {
                    return false;
                }

                if (!_cache.TryGetValue(CacheKey, out HashSet<string>? aliases))
                {
                    lock (CacheLock)
                    {
                        if (!_cache.TryGetValue(CacheKey, out aliases))
                        {
                            LoadFile();
                            _cache.TryGetValue(CacheKey, out aliases);
                        }
                    }
                }

                if (aliases.Contains(domain.ToLower()))
                {
                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                return null;
            }
        }

    }
}