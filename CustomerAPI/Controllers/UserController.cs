using CustomerAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CustomerAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AdminDBContext context;
        private readonly JWTSetting setting;
        private readonly IRefreshTokenGenerator tokenGenerator;
        public UserController(AdminDBContext context, IOptions<JWTSetting> options, IRefreshTokenGenerator _refreshToken)
        {
            this.context = context;
            this.setting = options.Value;
            this.tokenGenerator = _refreshToken;
        }

        [NonAction]
        public TokenResponse Authenticate(string username, Claim[] claims)
        {
            TokenResponse tokenResponse = new TokenResponse();

            var tokenKey = Encoding.UTF8.GetBytes(setting.securitykey);

            var tokenHandler = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(2),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256)
                );
            tokenResponse.JWTTokken = new JwtSecurityTokenHandler().WriteToken(tokenHandler);
            tokenResponse.RefreshTokken = tokenGenerator.GenerateToken(username);

            return tokenResponse;
        }

        [Route("Authenticate")]
        [HttpPost]
        public IActionResult Authenticate([FromBody] UserCred user)
        {
            TokenResponse tokenResponse = new TokenResponse();

            var _user = context.TblUsers.FirstOrDefault(o => o.Userid == user.username && o.Password == user.password);
            if(_user == null)
            {
                return Unauthorized();
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.UTF8.GetBytes(setting.securitykey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                    new Claim[]
                    {
                        new Claim(ClaimTypes.Name, _user.Userid),
                        new Claim(ClaimTypes.Role, _user.Role)
                    }
                ),
                Expires = DateTime.Now.AddMinutes(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            string finalToken = tokenHandler.WriteToken(token);

            tokenResponse.JWTTokken = finalToken;
            tokenResponse.RefreshTokken = tokenGenerator.GenerateToken(user.username);

            return Ok(tokenResponse);
        }

        [Route("Refresh")]
        [HttpPost]
        public IActionResult Refresh([FromBody] TokenResponse token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token.JWTTokken, new TokenValidationParameters {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(setting.securitykey)),
                ValidateIssuer = false,
                ValidateAudience = false
            }, out securityToken);

            var _token = securityToken as JwtSecurityToken;
            if(_token != null && !_token.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
            {
                return Unauthorized();
            }

            var username = principal.Identity!.Name;
            var _refTable = context.TblRefreshtokens.FirstOrDefault(o => o.UserId == username && o.RefreshToken == token.RefreshTokken);
            if(_refTable == null)
            {
                return Unauthorized();
            }

            TokenResponse _result = Authenticate(username!, principal.Claims.ToArray());

            return Ok(_result);
        }

        [Route("GetMenubyRole/{role}")]
        [HttpGet]
        public IActionResult GetMenubyRole(string role)
        {
            var _result = (from q1 in context.TblPermissions.Where(item => item.RoleId == role)
                           join q2 in context.TblMenus
                           on q1.MenuId equals q2.Id
                           select new { q1.MenuId, q2.Name, q2.LinkName }).ToList();
            // var _result = context.TblPermission.Where(o => o.RoleId == role).ToList();

            return Ok(_result);
        }

        [Route("HaveAccess")]
        [HttpGet]
        public IActionResult HaveAccess(string role, string menu)
        {
            APIResponse result = new APIResponse();
            //var username = principal.Identity.Name;
            var _result = context.TblPermissions.Where(o => o.RoleId == role && o.MenuId == menu).FirstOrDefault();
            if (_result != null)
            {
                result.result = "pass";
            }
            return Ok(result);
        }

        [Route("GetAllRole")]
        [HttpGet]
        public IActionResult GetAllRole()
        {
            var _result = context.TblRoles.ToList();
            // var _result = context.TblPermission.Where(o => o.RoleId == role).ToList();

            return Ok(_result);
        }

        [Route("GetAllStatus")]
        [HttpGet]
        public IActionResult GetAllStatus()
        {
            //var _result = context.TblUsers.ToList();
            var _result = context.TblUsers.Where(o => o.IsActive == true).ToList();

            return Ok(_result);
        }

        [HttpPost("Register")]
        public APIResponse Register([FromBody] TblUser value)
        {
            string result = string.Empty;
            try
            {
                var _emp = context.TblUsers.FirstOrDefault(o => o.Userid == value.Userid);
                if (_emp != null)
                {
                    result = string.Empty;
                }
                else
                {
                    TblUser tblUser = new TblUser()
                    {
                        Name = value.Name,
                        Email = value.Email,
                        Userid = value.Userid,
                        Role = string.Empty,
                        Password = value.Password,
                        IsActive = false
                    };
                    context.TblUsers.Add(tblUser);
                    context.SaveChanges();
                    result = "pass";
                }
            }
            catch (Exception ex)
            {
                result = string.Empty;
            }
            return new APIResponse { keycode = string.Empty, result = result };
        }
    }
}
