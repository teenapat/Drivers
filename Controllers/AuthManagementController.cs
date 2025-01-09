using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Drivers.Api.Configurations;
using Drivers.Api.Models.DTOs;
using Drivers.Api.Models.Token;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Drivers.Api.Controllers;

[Route("api/[controller]")]
public class AuthManagementController : ControllerBase
{
    private readonly ILogger<AuthManagementController> _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtConfig _jwtConfig;
    private readonly IConfiguration _configuration;

    public AuthManagementController(
        ILogger<AuthManagementController> logger,
        UserManager<ApplicationUser> userManager,
        IOptionsMonitor<JwtConfig> optionsMonitor,
        IConfiguration configuration)
    {
        _logger = logger;
        _userManager = userManager;
        _jwtConfig = optionsMonitor.CurrentValue;
        _configuration = configuration;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Regitter([FromBody] UserRegistrationRequestDto requestDto)
    {
        if (ModelState.IsValid)
        {
            var emailExist = await _userManager.FindByEmailAsync(requestDto.Email);

            if (emailExist != null)
            {
                return BadRequest("email already exist");
            }

            var newUser = new ApplicationUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Email
            };

            var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);

            if (isCreated.Succeeded)
            {
                var token = GenerateJwtToken(newUser);
                return Ok(new RegistrationRequestResponse()
                {
                    Result = true,
                    Token = token
                });
            }

            return BadRequest(isCreated.Errors.Select(x => x.Description).ToList());
        }

        return BadRequest("Invalid request payload");
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto)
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _userManager.FindByEmailAsync((requestDto.Email));

            if (existingUser == null)
            {
                return BadRequest("Invalid authentication");
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(existingUser, requestDto.Password);

            if (isPasswordValid)
            {
                var token = GenerateJwtToken(existingUser);
                var refreshToken = GenerateRefreshToken();

                _ = int.TryParse(_configuration["JwtConfig:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

                existingUser.RefreshToken = refreshToken;
                existingUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                await _userManager.UpdateAsync(existingUser);

                return Ok(new LoginRequestResponse()
                {
                    Token = token,
                    Result = true,
                    RefreshToken = refreshToken
                });
            }

            return BadRequest("Invalid authentication");
        }
        return BadRequest("Invalid request payload");
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
        _ = int.TryParse(_configuration["JwtConfig:tokenValidityInMinutes"], out int tokenValidityInMinutes);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new []
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.Email),
            }),
            Issuer = _configuration["JwtConfig:ValidIssuer"],
            Audience = _configuration["JwtConfig:ValidAudience"],
            NotBefore = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512)
        };
        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);
        return jwtToken;
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenModel? tokenModel)
    {
        if (tokenModel is null)
        {
            return BadRequest("Invalid client request");
        }

        string? accessToken = tokenModel.AccessToken;
        string? refreshToken = tokenModel.RefreshToken;

        var principal = GetPrincipalFromExpiredToken(accessToken);
        if (principal == null)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        string? emailName = principal.Identity?.Name;

        var user = await _userManager.FindByEmailAsync(emailName);

        if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var newAccessToken = GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await _userManager.UpdateAsync(user);

        return Ok(new LoginRequestResponse()
        {
            Token = newAccessToken,
            Result = true,
            RefreshToken = newRefreshToken
        });

    }

    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
    {
        var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512,
                StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

}
