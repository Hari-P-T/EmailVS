using DnsClient;
using EmailAddressVerification.Services;
using EmailAddressVerificationAPI.Models;
using Service.Services;
using System.Text.RegularExpressions;

namespace EmailAddressVerificationAPI.Services
{
    public class DomainVerification
    {
        private WhiteListedEmailProvider _whiteListedEmailProvider;
        private TopLevelDomainVerification _topLevelDomainVerifier;
        private VulgarWordSearch _vulgarWordsChecker;
        private DisposableDomainsCheck _disposableDomainsCheker;
        private GreyListedDomainsCheck _greylistedDomainsChecker;
        private BlackListedDomainsCheck _blacklistedDomainsChecker;
        private SpfCheck _spfCheck;
        private DmarckCkeck _dmarckCheck;
        private MXRecordChecker _mxRecordChecker;
        private List<string> _mxRecords = new List<string>();
        private string _parentDomain = string.Empty;
        private SmtpValidator _smtpServerVerification;
        private DkimCkeck _dkimCheck;
        private AliasUsernameCheck _aliasUsernameCheck;

        public DomainVerification(WhiteListedEmailProvider whiteListedEmailProvider, TopLevelDomainVerification topLevelDomainVerifier, VulgarWordSearch vulgarWordVerifier, DisposableDomainsCheck disposableDomainsCheker, SmtpValidator smtpServerVerification, GreyListedDomainsCheck greylistedDomainsChecker, BlackListedDomainsCheck blacklistedDomainsChecker, AliasUsernameCheck aliasUsernameCheck, SpfCheck spfCheck, DmarckCkeck dmarckCkeck, MXRecordChecker mxRecordChecker, DkimCkeck dkimCheck)
        {
            _whiteListedEmailProvider = whiteListedEmailProvider;
            _topLevelDomainVerifier = topLevelDomainVerifier;
            _vulgarWordsChecker = vulgarWordVerifier;
            _disposableDomainsCheker = disposableDomainsCheker;
            _smtpServerVerification = smtpServerVerification;
            _greylistedDomainsChecker = greylistedDomainsChecker;
            _blacklistedDomainsChecker = blacklistedDomainsChecker;
            _aliasUsernameCheck = aliasUsernameCheck;
            _spfCheck = spfCheck;
            _dmarckCheck = dmarckCkeck;
            _mxRecordChecker = mxRecordChecker;
            _dkimCheck = dkimCheck;
        }

        public async Task<bool?> HasVulgarWords(string userName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userName)) return false;

                return await _vulgarWordsChecker.HasVulgarWordsAsync(userName);
            }
            catch (Exception)
            {
                return null;
            }
        }


        private async Task<bool?> IsDomainWhitelisted(string parentDomain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(parentDomain)) return false;
                Console.WriteLine(parentDomain);
                var res = await _whiteListedEmailProvider.IsWhitelisted(parentDomain);
                Console.WriteLine("Result "+ res);
                return res;

            }
            catch (Exception)
            {
                return null;
            }
        }
        private async Task<bool?> IsTldRegistered(string tld)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(tld)) return false;
                return await _topLevelDomainVerifier.IsRegisteredTLD(tld);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<bool?> IsDisposableDomain(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;

                return await _disposableDomainsCheker.IsDisposableDomain(domain);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<bool?> IsGreyListedDomain(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;
                return await _greylistedDomainsChecker.IsGreyListedDomain(domain);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<bool?> IsBlackListedDomain(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;
                return await _blacklistedDomainsChecker.IsBlackListedDomain(domain);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<bool?> IsAlias(string username)
        {
            try
            {
                if (string.IsNullOrEmpty(username)) return false;
                return await _aliasUsernameCheck.IsAliasUsername(username);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static bool IsValidEmailSyntax(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            string pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            bool result= Regex.IsMatch(email, pattern);
            Console.WriteLine(result);
            return result;
        }

        private static bool IsValidDomainSyntax(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            string pattern = @"^(?!\-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$";
            return Regex.IsMatch(domain, pattern);
        }

        private static bool IsNotGarbageUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            string pattern = @"^(?!.*[._-]{2})(?![._-])[a-zA-Z0-9._-]{3,20}(?<![._-])$";
            return Regex.IsMatch(username, pattern);
        }

        private bool HasMxRecords(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;
                _mxRecords = _mxRecordChecker.GetMXRecordsAsync(domain).Result;
                _parentDomain = _mxRecordChecker.GetParentDomain(_mxRecords);
                if (_mxRecords.Count>0) return true;
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private bool SMTPCheck(string email, string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(domain)) return false;
                return _smtpServerVerification.IsSMTPValid(email, domain, _mxRecords).Result;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async Task<bool?> DKIMCheck()
        {
            try
            {
                return await _dkimCheck.HasAnyDkimRecord(_parentDomain);
            }
            catch (Exception)
            {
                return null ;
            }
        }

        public async Task<ResponseDTO> VerifyEmailDomain(string emailAddress, int strictness)
        {
            try
            {

                ResponseDTO _responseDTO = new ResponseDTO(new List<ChecklistElementDTO>());
                _responseDTO.EmailAddress = emailAddress;

                var userName = emailAddress.Split('@').FirstOrDefault();
                var domain = emailAddress.Split('@').LastOrDefault();
                var domainParts = domain.Split('.');
                string tld = domainParts[^1].ToLower();

                    var regexCheck1 = new ChecklistElementDTO
                    {
                        Name = "IsValidEmailSyntax",
                        WeightageAllocated = 10,
                        IsVerified = IsValidEmailSyntax(emailAddress)
                    };

                    _responseDTO.ChecklistElements.Add(regexCheck1);
                    Console.WriteLine("c1 done");

                    if (regexCheck1.IsVerified == true)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = regexCheck1.WeightageAllocated;
                        _responseDTO.TotalScore += regexCheck1.WeightageAllocated;
                    }


                    var regexCheck2 = new ChecklistElementDTO
                    {
                        Name = "IsValidDomainSyntax",
                        WeightageAllocated = 10,
                        IsVerified = IsValidDomainSyntax(domain)
                    };

                    _responseDTO.ChecklistElements.Add(regexCheck2);
                    Console.WriteLine("c2 done");

                    if (regexCheck2.IsVerified == true)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = regexCheck2.WeightageAllocated;
                        _responseDTO.TotalScore += regexCheck2.WeightageAllocated;
                    }

                    var regexCheck3 = new ChecklistElementDTO
                    {
                        Name = "IsNotGarbageUsername",
                        WeightageAllocated = 10,
                        IsVerified = IsNotGarbageUsername(userName)
                    };

                    _responseDTO.ChecklistElements.Add(regexCheck3);
                    Console.WriteLine("c3 done");

                    if (regexCheck3.IsVerified == true)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = regexCheck3.WeightageAllocated;
                        _responseDTO.TotalScore += regexCheck3.WeightageAllocated;
                    }



                    var tldCheck = new ChecklistElementDTO
                    {
                        Name = "IsRegisteredTLD",
                        WeightageAllocated = 10,
                        IsVerified = await IsTldRegistered(tld)
                    };
                    _responseDTO.ChecklistElements.Add(tldCheck);
                    Console.WriteLine("c4 done");

                    if (tldCheck.IsVerified==true)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = tldCheck.WeightageAllocated;
                        _responseDTO.TotalScore += tldCheck.ObtainedScore;
                    }


                    //smtpVerificationResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);
                    var domainMxRecordStatus = HasMxRecords(domain);
                Console.WriteLine(_parentDomain + " - pd");
                var parentDomainMxRecordStatus = HasMxRecords(_parentDomain);
                var overAllMxStatus = domainMxRecordStatus && parentDomainMxRecordStatus;
                var mxRecordsCheck = new ChecklistElementDTO
                    {
                        Name = "HasMxRecords",
                        WeightageAllocated = 10,
                        IsVerified = overAllMxStatus
                    };

                    mxRecordsCheck.ObtainedScore = (mxRecordsCheck.IsVerified == true) ? mxRecordsCheck.WeightageAllocated : 0;

                    _responseDTO.ChecklistElements.Add(mxRecordsCheck);
                    Console.WriteLine("c5 done");
                    _responseDTO.TotalScore += mxRecordsCheck.ObtainedScore;


                    var smtpCheck = new ChecklistElementDTO
                    {
                        Name = "SMTPcheck",
                        WeightageAllocated = 10,
                        IsVerified = SMTPCheck(emailAddress,domain)
                    };

                    smtpCheck.ObtainedScore = (smtpCheck.IsVerified == true) ? smtpCheck.WeightageAllocated : 0;
                    _responseDTO.ChecklistElements.Add(smtpCheck);
                    Console.WriteLine("c6 done");
                    _responseDTO.TotalScore += smtpCheck.ObtainedScore;

                    var spfDomainResult = await _spfCheck.CheckSPFAsync(domain);
                Console.WriteLine("c7.0 done");
                Console.WriteLine(_parentDomain + "- pd -");
                //var spfParentResult = await _spfCheck.CheckSPFAsync(_parentDomain);
                    //var spfResult = spfDomainResult == true && spfParentResult == true;

                var spfCheck = new ChecklistElementDTO
                    {
                        Name = "HasSpfRecords",
                        WeightageAllocated = 10,
                        IsVerified = spfDomainResult
                };

                    spfCheck.ObtainedScore = (spfCheck.IsVerified==true)?spfCheck.WeightageAllocated : 0;
                    _responseDTO.ChecklistElements.Add(spfCheck);

                    _responseDTO.TotalScore += spfCheck.ObtainedScore;

                Console.WriteLine("c7.1 done");

                var dmarkCheck = new ChecklistElementDTO
                    {
                        Name = "HasDmarcRecords",
                        WeightageAllocated = 10,
                        IsVerified = await _dmarckCheck.HasValidDmarcPolicy(domain)
                    };

                    dmarkCheck.ObtainedScore = (dmarkCheck.IsVerified==true)?dmarkCheck.WeightageAllocated : 0;

                    _responseDTO.ChecklistElements.Add(dmarkCheck);

                    _responseDTO.TotalScore += dmarkCheck.ObtainedScore;

                    var disposableDomainCheck = new ChecklistElementDTO
                    {
                        Name = "IsNotDisposableDomain",
                        WeightageAllocated = 10,
                        IsVerified = await IsDisposableDomain(domain)
                    };
                    disposableDomainCheck.ObtainedScore = (disposableDomainCheck.IsVerified==true)?disposableDomainCheck.WeightageAllocated : 0;
                _responseDTO.ChecklistElements.Add(disposableDomainCheck);

                    if (disposableDomainCheck.IsVerified==true)
                    {
                        _responseDTO.TotalScore += disposableDomainCheck.ObtainedScore;
                    }

                    var whiteListCheck = new ChecklistElementDTO
                    {
                        Name = "IsWhiteListed",
                        WeightageAllocated = 10,
                        IsVerified = await IsDomainWhitelisted(_parentDomain)
                    };
                    whiteListCheck.ObtainedScore = (whiteListCheck.IsVerified==true)?whiteListCheck.WeightageAllocated : 0;

                _responseDTO.ChecklistElements.Add(whiteListCheck);

                    if (whiteListCheck.IsVerified==true)
                    {
                        _responseDTO.TotalScore += whiteListCheck.ObtainedScore;
                    }

                    var greyListCheck = new ChecklistElementDTO
                    {
                        Name = "IsNotGreyListed",
                        WeightageAllocated = 10,
                        IsVerified = await IsGreyListedDomain(domain)
                    };
                    greyListCheck.ObtainedScore = (greyListCheck.IsVerified==true)?greyListCheck.WeightageAllocated : 0;
                _responseDTO.ChecklistElements.Add(greyListCheck);

                    if (greyListCheck.IsVerified == true)
                    {
                        _responseDTO.TotalScore += greyListCheck.ObtainedScore;
                    }

                    var blacklistCheck = new ChecklistElementDTO
                    {
                        Name = "IsNotBlackListed",
                        WeightageAllocated = 10,
                        IsVerified = await IsBlackListedDomain(domain)
                    };
                    blacklistCheck.ObtainedScore = (blacklistCheck.IsVerified==true)?blacklistCheck.WeightageAllocated : 0;
                _responseDTO.ChecklistElements.Add(blacklistCheck);

                if (blacklistCheck.IsVerified == true)
                {
                    _responseDTO.TotalScore += greyListCheck.ObtainedScore;
                }

                var vulgarCheck = new ChecklistElementDTO
                    {
                        Name = "NotContainsVulgar",
                        WeightageAllocated = 10,
                        IsVerified = await HasVulgarWords(userName)
                    };
                    vulgarCheck.ObtainedScore = (vulgarCheck.IsVerified==true)?vulgarCheck.WeightageAllocated : 0;
                _responseDTO.ChecklistElements.Add(vulgarCheck);
                if (vulgarCheck.IsVerified == true)
                {
                    _responseDTO.TotalScore += greyListCheck.ObtainedScore;
                }

                var aliasCheck = new ChecklistElementDTO
                {
                    Name = "IsLikelyAlias",
                    WeightageAllocated = 10,
                    IsVerified = await IsAlias(userName)
                };
                aliasCheck.ObtainedScore = (aliasCheck.IsVerified == false) ? aliasCheck.WeightageAllocated : 0;
                _responseDTO.ChecklistElements.Add(aliasCheck);

          

                    var dkimCheck = new ChecklistElementDTO
                    {
                        Name = "HasDkimRecords",
                        WeightageAllocated = 10,
                        IsVerified = await DKIMCheck()
                    };

                    dkimCheck.ObtainedScore = (dkimCheck.IsVerified==true)?dkimCheck.WeightageAllocated : 0;
                    _responseDTO.ChecklistElements.Add(dkimCheck);


                     var catchAllStatus = await _smtpServerVerification.IsCatchAllAsync(domain, _mxRecords.FirstOrDefault());
                Console.WriteLine(catchAllStatus);

                if (catchAllStatus == true
                     && vulgarCheck.IsVerified == true && smtpCheck.IsVerified == true && disposableDomainCheck.IsVerified == true
                    && spfCheck.IsVerified == true
                    && dmarkCheck.IsVerified == true
                    && blacklistCheck.IsVerified == true
                    && mxRecordsCheck.IsVerified == true)
                {
                    _responseDTO.Status = "Catch All";
                }
                else if (vulgarCheck.IsVerified == true && smtpCheck.IsVerified==true && disposableDomainCheck.IsVerified==true
                    && spfCheck.IsVerified ==true 
                    && dmarkCheck.IsVerified ==true
                    && blacklistCheck.IsVerified ==true
                    && mxRecordsCheck.IsVerified ==true
                    )
                {
                    _responseDTO.Status = "Valid";
                }
                else
                {
                    _responseDTO.Status = "InValid";
                }

                    _responseDTO.TotalScore += dkimCheck.ObtainedScore;
                    //_responseDTO.Status = 

                return _responseDTO;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}