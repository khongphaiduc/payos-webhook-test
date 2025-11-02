using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;

namespace payos_test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class payostestController : ControllerBase
    {
        private readonly string _checksumKey = "yourchecksumkey";

        [HttpPost("webhooktest")]
        public IActionResult ReceiveWebhook([FromBody] JsonElement webhook)
        {

            // Lấy trường data
            JsonElement data = webhook.GetProperty("data");


            // Lấy signature từ payload
            string signatureFromPayOS = webhook.GetProperty("signature").GetString() ?? "";


            // Tạo dictionary chứa tất cả key/value trong data
            SortedDictionary<string, string> dict = new SortedDictionary<string, string>(); // tự sort A-Z


            foreach (JsonProperty prop in data.EnumerateObject())
            {
                string key = prop.Name;
                string value = prop.Value.ToString() ?? "";
                value = Uri.EscapeDataString(value); // encode đúng chuẩn
                dict.Add(key, value);
            }


            // Ghép thành chuỗi key=value&key=value...
            string dataString = string.Join("&", dict.Select(x => $"{x.Key}={x.Value}"));




            // Tính signature  bên backend của mình  
            string localSignature = CreateSignature(dataString, _checksumKey);





            //  nếu signature bên mình không khớp với bên PayOS → từ chối
            if (!localSignature.Equals(signatureFromPayOS, StringComparison.OrdinalIgnoreCase))
                return BadRequest("Invalid signature");




            // ---- Webhook hợp lệ → xử lý đơn hàng ----
            string orderCode = data.GetProperty("orderCode").ToString();
            string amount = data.GetProperty("amount").ToString();

            Console.WriteLine($"✅ Webhook OK | Order: {orderCode} | Amount: {amount}");

            return Ok(new { seccuss = "true", datas = data });
        }


        public string CreateSignature(string rawData, string checksumKey)
        {
            // checksumKey là key HMAC
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(checksumKey)))
            {
                byte[] data = Encoding.UTF8.GetBytes(rawData);    // chuyển data thành mảng  byte

                byte[] hash = hmac.ComputeHash(data); // rawData là canonical string
                return BitConverter.ToString(hash).Replace("-", "").ToLower();   // chuyển về  string hex   
            }
        }

    }
}
