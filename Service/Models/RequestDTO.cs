﻿namespace EmailAddressVerificationAPI.Models
{
    public class RequestDTO
    {
        public string Email { get; set; }

        public int Timeout { get; set; } = 10000;

        public int Strictness { get; set; } = 2;
    }
}
