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


        private async Task<bool?> IsDomainWhitelisted(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;
                var res = await _whiteListedEmailProvider.IsWhitelisted(domain);
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

        private async Task<bool> HasMxRecords(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return false;
                _mxRecords = await _mxRecordChecker.GetMXRecordsAsync(domain);
                _parentDomain = _mxRecordChecker.GetParentDomain(_mxRecords);
                var res = await _spfCheck.CheckSPFAsync(_parentDomain);
                if (_mxRecords.Count>0 && res ==true) return true;
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

                    if (tldCheck.IsVerified==true)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = tldCheck.WeightageAllocated;
                        _responseDTO.TotalScore += tldCheck.ObtainedScore;
                    }


                    //smtpVerificationResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);

                    var mxRecordsCheck = new ChecklistElementDTO
                    {
                        Name = "HasMxRecords",
                        WeightageAllocated = 10,
                        IsVerified = await HasMxRecords(domain)
                    };

                    mxRecordsCheck.ObtainedScore = (mxRecordsCheck.IsVerified == true) ? mxRecordsCheck.WeightageAllocated : 0;

                    _responseDTO.ChecklistElements.Add(mxRecordsCheck);
                    _responseDTO.TotalScore += mxRecordsCheck.ObtainedScore;


                    var smtpCheck = new ChecklistElementDTO
                    {
                        Name = "SMTPcheck",
                        WeightageAllocated = 10,
                        IsVerified = SMTPCheck(emailAddress,domain)
                    };

                    smtpCheck.ObtainedScore = (smtpCheck.IsVerified == true) ? smtpCheck.WeightageAllocated : 0;
                    _responseDTO.ChecklistElements.Add(smtpCheck);
                    _responseDTO.TotalScore += smtpCheck.ObtainedScore;

                    var spfCheck = new ChecklistElementDTO
                    {
                        Name = "HasSpfRecords",
                        WeightageAllocated = 10,
                        IsVerified =  await _spfCheck.CheckSPFAsync(domain)
                    };

                    spfCheck.ObtainedScore = (spfCheck.IsVerified==true)?spfCheck.WeightageAllocated : 0;
                    _responseDTO.ChecklistElements.Add(spfCheck);

                    _responseDTO.TotalScore += spfCheck.ObtainedScore;



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

                    Console.WriteLine("At Domain Verification parent Domain Sttus "+_parentDomain);
                var parentMXRecordResult =  await HasMxRecords(_parentDomain);

               

                 var catchAllStatus = await _smtpServerVerification.IsCatchAllAsync(domain, _mxRecords.FirstOrDefault());
                Console.WriteLine("catch All status "+catchAllStatus);

               
                 if (smtpCheck.IsVerified==true
                    && mxRecordsCheck.IsVerified ==true
                    &&parentMXRecordResult ==true
                    && catchAllStatus ==false
                    && blacklistCheck.IsVerified ==true
                    && vulgarCheck.IsVerified ==true
                    )
                {
                    _responseDTO.Status = "Valid";
                }
                else if(catchAllStatus == true && parentMXRecordResult ==true ) 
                {
                    _responseDTO.Status = "Catch All";
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