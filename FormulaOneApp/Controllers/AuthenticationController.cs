using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FormulaOneApp.Configurations;
using FormulaOneApp.Data;
using FormulaOneApp.Models;
using FormulaOneApp.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using RestSharp.Authenticators;

namespace FormulaOneApp.Controllers;

[Route("api/[controller]")] // api/authentication
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly TokenValidationParameters _tokenValidationParams;

    private readonly AppDbContext _context;
    //private readonly JwtConfig _jwtConfig;

    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        IConfiguration configuration,
        AppDbContext context,
        TokenValidationParameters tokenValidationParameters
        //JwtConfig jwtConfig
        )
    {
        _context = context;
        _userManager = userManager;
        //_jwtConfig = jwtConfig;
        _configuration = configuration;
        _tokenValidationParams = tokenValidationParameters;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
    {
        // Validate the incoming request
        if (ModelState.IsValid)
        {
            // We need to check if the email already exist
            var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);

            if (user_exist != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exist"
                    }
                });
            }
            
            // create a user
            var new_user = new IdentityUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Email,
                EmailConfirmed = false
            };

            var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);

            if (is_created.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(new_user);
                   
                var email_body = "Please confirm your email address <a href=\"#URL#\">Click here </a> ";
                
                // https://localhost:8080/authentication/verifyemail/userid=sdas&code=dasdasd 
                var callback_url = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication",
                    new {userId = new_user.Id, code = code});

                var body = email_body.Replace("#URL#",
                    callback_url);

                // SEND EMAIL
                var result = SendEmail(body, new_user.Email);
                
                if (result)
                    return Ok("Please verify your email, through the verification email we have just sent.");
                
                return Ok("Please request an email verification link");
                // Generate the token
                //var token = GenerateJwtToken(new_user);

                // return Ok(new AuthResult()
                // {
                //     Result = true,
                //     Token = token
                // });
            }

            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Server error"
                },
                Result = false
            });
        }

        return BadRequest();
    }

    [Route("ConfirmEmail")]
    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (userId == null || code == null)
        {
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Invalid email confirmation url"
                }
            });
        }

        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Invalid email parameter"
                }
            });
        }

        //code =  Encoding.UTF8.GetString(Convert.FromBase64String(code));
        var result = await _userManager.ConfirmEmailAsync(user, code);
        var status = result.Succeeded
            ? "Thank you for confirming your mail"
            : "Your email is not confirmed, please try again later";
        
        return Ok(status);
    }

    [Route("Login")]
    [HttpPost]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
    {
        if (ModelState.IsValid)
        {
            // Check if the user exist
            var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);

            if (existing_user == null)
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid payload"
                    },
                    Result = false
                });
            
            // if(!existing_user.EmailConfirmed)
            //     return BadRequest(new AuthResult()
            //     {
            //         Errors = new List<string>()
            //         {
            //             "Email needs to be confirmed"
            //         },
            //         Result = false
            //     });

            var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);

            if (!isCorrect)
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid credentials"
                    },
                    Result = false
                });

            var jwtToken = await GenerateJwtToken(existing_user);

            return Ok(jwtToken);
        }

        return BadRequest(new AuthResult()
        {
            Errors = new List<string>()
            {
                "Invalid payload"
            },
            Result = false
        });
    }

    private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
        
        // Token descriptor
        var tokenDescriptor = new SecurityTokenDescriptor() 
        {
            Subject = new ClaimsIdentity(new []
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, value:user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
            }),
            
            Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)) ,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            Token = RandomStringGeneration(23), // Generate a refresh token
            AddedDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddMonths(6),
            IsRevoked = false,
            IsUsed = false,
            UserId = user.Id
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();
        
        return new AuthResult()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            Result = true
        };
    }

    [HttpPost]
    [Route("RefreshToken")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
    {
        if (ModelState.IsValid)
        {
            var result = await VerifyAndGenerateToken(tokenRequest);
            
            if(result == null)
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid tokens"
                    },
                    Result = false
                });

            return Ok(result);
        }

        return BadRequest(new AuthResult()
        {
            Errors = new List<string>()
            {
                "Invalid parameters"
            },
            Result = false
        });
    }

    private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            _tokenValidationParams.ValidateLifetime = false; // for testing

            var tokenInVerification =
                jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validedToken);

            if (validedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase);

                if (result == false)
                    return null;
            }

            var utcExpiryDate = long.Parse(tokenInVerification.Claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);


            var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
            if (expiryDate > DateTime.Now)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Expired token"
                    }
                };
            }

            var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

            if (storedToken == null)
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid tokens"
                    }
                };
            
            if(storedToken.IsUsed)
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid tokens"
                    }
                };
            
            if(storedToken.IsRevoked)
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid tokens"
                    }
                };

            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            
            if(storedToken.JwtId != jti)
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid tokens"
                    }
                };
            
            if(storedToken.ExpiryDate < DateTime.UtcNow)
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Expired tokens"
                    }
                };


            storedToken.IsUsed = true;
            _context.RefreshTokens.Update(storedToken);
            await _context.SaveChangesAsync();

            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
            return await GenerateJwtToken(dbUser);
        }
        catch (Exception e)
        {
            return new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Server error"
                }
            };
        }
    }

    private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
    {
        var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();

        return dateTimeVal;
    }

    private bool SendEmail(string body, string email)
    {
        // Create client
        var client = new RestClient("https://api.mailgun.net/v3");

        var request = new RestRequest("", Method.Post);

        client.Authenticator = 
            new HttpBasicAuthenticator("api", _configuration.GetSection("EmailConfig:API_KEY").Value);

        request.AddParameter("domain", "sandbox6f6517f9e5da43cab8f3d5897b327d9f.mailgun.org", ParameterType.UrlSegment);
        request.Resource = "{domain}/messages";
        request.AddParameter("from", "Mailgun Sandbox <postmaster@sandbox6f6517f9e5da43cab8f3d5897b327d9f.mailgun.org>");
        request.AddParameter("to", "hello@mohamadlawand.com");
        request.AddParameter("subject", "Email Verification ");
        request.AddParameter("text", body);
        request.Method = Method.Post;

        var response = client.Execute(request);

        return response.IsSuccessful;
    }

    private string RandomStringGeneration(int length)
    {
        var random = new Random();
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
        return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}