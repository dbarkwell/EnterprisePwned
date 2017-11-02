using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using EnterprisePwned.Data;

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EnterprisePwned
{
    public static class ScanEmail
    {
        private static HttpClient client;

        [FunctionName("ScanEmail")]
        public static async Task Run([TimerTrigger("0 0 0 * * 0")]TimerInfo myTimer, TraceWriter log)
        {
            try
            {
                var tenant = GetEnvironmentVariable("Tenant");
                var clientId = GetEnvironmentVariable("ClientId");
                var clientSecret = GetEnvironmentVariable("ClientSecret");
                var siteId = GetEnvironmentVariable("SiteId");
                var listId = GetEnvironmentVariable("ListId");

                var token = await AppAuthenticationAsync(tenant, clientId, clientSecret);

                client = new HttpClient();

                var emailAddresses = await GetUsersEmailAddress(token);

                var pwned = await HaveIBeenPwned(emailAddresses);

                await UpdateSecurityList(TransformPwnedResponse(pwned), token, siteId, listId);
            }
            catch (Exception e)
            {
                log.Error(e.Message);
            }
            finally
            {
                client?.Dispose();
            }
        }

        private static async Task<string> AppAuthenticationAsync(string tenant, string clientId, string secret)
        {
            using (var webClient = new WebClient())
            {
                var requestParameters =
                    new NameValueCollection
                        {
                            { "resource", "https://graph.microsoft.com/" },
                            { "client_id", clientId },
                            { "grant_type", "client_credentials" },
                            { "client_secret", secret }
                        };

                var url = $"https://login.microsoftonline.com/{tenant}/oauth2/token";
                var responsebytes = await webClient.UploadValuesTaskAsync(url, "POST", requestParameters);
                var responsebody = Encoding.UTF8.GetString(responsebytes);
                var obj = JsonConvert.DeserializeObject<JObject>(responsebody);
                var token = obj["access_token"].Value<string>();

                return token;
            }
        }

        private static string GetEnvironmentVariable(string variableName)
        {
            return Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.Process);
        }

        private static async Task<IEnumerable<User>> GetUsersEmailAddress(string token)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await client.GetAsync("https://graph.microsoft.com/v1.0/users?$select=mail");
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(content);
            }

            var emailAddresses = JsonConvert.DeserializeObject<UserResponse>(content);

            return emailAddresses.Value;
        }

        private static async Task<IEnumerable<PwnedResponse>> HaveIBeenPwned(IEnumerable<User> addresses)
        {
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("User-Agent", "Enterprise-Pwned");
            var pwnedList = new List<PwnedResponse>();

            foreach (var address in addresses)
            {
                if (string.IsNullOrWhiteSpace(address.Mail)) continue;

                var response = await client.GetAsync(
                                   $"https://haveibeenpwned.com/api/v2/breachedaccount/{address.Mail}");

                if (!response.IsSuccessStatusCode)
                {
                    Thread.Sleep(1500);
                    continue;
                }

                var pwned = await response.Content.ReadAsStringAsync();
                pwnedList.Add(
                    new PwnedResponse
                        {
                            EmailAddress = address.Mail,
                            Pwned = JsonConvert.DeserializeObject<JArray>(pwned)
                                .ToObject<IEnumerable<Pwned>>()
                        });

                Thread.Sleep(1500);
            }

            return pwnedList;
        }

        private static IEnumerable<Fields> TransformPwnedResponse(IEnumerable<PwnedResponse> response)
        {
            var fields = new List<Fields>();
            foreach (var resp in response) fields.AddRange(TransformPwnedToFields(resp.EmailAddress, resp.Pwned));

            return fields;
        }

        private static IEnumerable<Fields> TransformPwnedToFields(string email, IEnumerable<Pwned> pwned)
        {
            return pwned.Select(
                pwn => new Fields
                           {
                               Title = email,
                               AddedDate = pwn.AddedDate,
                               BreachDate = pwn.BreachDate,
                               Description = pwn.Description,
                               ModifiedDate = pwn.ModifiedDate,
                               Name = pwn.Name,
                               Title0 = pwn.Title,
                               Domain = pwn.Domain
                           }).ToList();
        }

        private static async Task UpdateSecurityList(
            IEnumerable<Fields> pwnedList,
            string token,
            string siteId,
            string listId)
        {
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            foreach (var fields in pwnedList)
            {
                var payload = JsonConvert.SerializeObject(new { fields });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                await client.PostAsync(
                    $"https://graph.microsoft.com/beta/sites/{siteId}/lists/{listId}/items",
                    content);
            }
        }
    }
}