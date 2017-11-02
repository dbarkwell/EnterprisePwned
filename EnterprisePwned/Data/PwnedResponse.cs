using System.Collections.Generic;

namespace EnterprisePwned.Data
{
    public class PwnedResponse
    {
        public string EmailAddress { get; set; }

        public IEnumerable<Pwned> Pwned { get; set; }
    }
}