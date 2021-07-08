using System.Collections.Generic;
// JWT package: https://github.com/jwt-dotnet/jwt
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.AspNetCore.Mvc;

namespace DeploymentsAdvancedSecurity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class PortalAdvancedSecurityController : ControllerBase
    {
        // This should go from config.
        private static readonly string DEPLOYMENT_1_ID = "deployment_cQPneKKawjVsample";

        private static readonly string DEPLOYMENT_1_MASTER_KEY = "key_XREeuYWSOkfG1UcYY4TqOs52US3fSlEj97Zldoc" +
                                                                 "MQUbRZXUiOxXxj7IXR8RvPRr2ACqsiaX2xIaDaVu22l" +
                                                                 "dXYfDpvLvUoBNaWKZxUAtkXbJ3nxh2jKihuJJE9Gsample";

        private static readonly string DEPLOYMENT_2_ID = "deployment_F2fHsQkpBoPsample";

        private static readonly string DEPLOYMENT_2_MASTER_KEY = "key_c2C1OPimUlnhAgZq4PSWhYmKe77DfdhnHMv8WII" +
                                                                 "VXdHNBOXvyKwRgZQyLa8n8ppf7ddguJpu6Wlbk6a7y1" +
                                                                 "xGPaeSAeDDxLPcJuTiZ73gOVtC5tcyQbT2oHePL6sample";

        private Dictionary<string, string> _deploymentKeyMap = new Dictionary<string, string>
        {
            {DEPLOYMENT_1_ID, DEPLOYMENT_1_MASTER_KEY},
            {DEPLOYMENT_2_ID, DEPLOYMENT_2_MASTER_KEY},
        };

        private string GenerateToken(string masterKey)
        {
            var payload = new Dictionary<string, object>();

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            return encoder.Encode(payload, masterKey);
        }
        
        /// <summary>Validate user access and generate a JWT token.
        /// <example>Example request:
        /// https://example.com/?deployment=deployment_cQPneKKawjVsample
        /// results in <c>{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.wbik0h1DuJ4cCp1V_QfiB7fIVHoERdVRkDsdXY6BxlA"}</c>
        /// </example>
        /// </summary>
        [HttpGet]
        public IActionResult Get([FromQuery] string deployment)
        {
            if (string.IsNullOrEmpty(deployment))
            {
                return BadRequest("Missing `deployment` query param.");
            }

            if (!_deploymentKeyMap.TryGetValue(deployment, out var masterKey))
            {
                return NotFound("Deployment not found.");
            }

            var token = GenerateToken(masterKey);
            var retval = new Dictionary<string, string>
            {
                {"token", token},
            };

            return Ok(retval);
        }
    }
}
