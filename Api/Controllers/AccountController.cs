﻿using Api.DTOs.Account;
using Api.Models;
using Api.Services;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JWTService _jwtService;
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly EmailService _emailService;
        private readonly IConfiguration _config;
        private readonly HttpClient _facebookHttpClient;

        [Authorize]
        [HttpGet("refresh-user-token")]
        public async Task<ActionResult<UserDto>> RefreshUserToken()
        {
            var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);
            return CreateApplicationUserDto(user);
        }
        public AccountController(JWTService jwtService, 
            SignInManager<User> signInManager, 
            UserManager<User> userManager, 
            EmailService emailService,
            IConfiguration config
            )
        {
            _jwtService = jwtService;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailService = emailService;
            _config = config;
            _facebookHttpClient = new HttpClient
            {
                BaseAddress = new Uri("https://graph.facebook.com")
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null)  return Unauthorized("Invalid username or password");
            if (user.EmailConfirmed == false) return Unauthorized("Please confirm your email.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password,false);
            
            if(!result.Succeeded) return Unauthorized("Invalid username or password");

            return CreateApplicationUserDto(user);
        }

        [HttpPost("login-with-third-party")]
        public async Task<ActionResult<UserDto>> LoginWithThirdParty(LoginWithExternalDto model)
        {
            if (model.Provider.Equals(SD.Facebook))
            {
                try
                {
                    if (!FacebookValidatedAsync(model.Accesstoken, model.UserId).GetAwaiter().GetResult())
                    {
                        return Unauthorized("Unable to login with Facebook");
                    }
                }
                catch (Exception)
                {
                    return Unauthorized("Unable to login with Facebook");
                }

            }
            else if (model.Provider.Equals(SD.Google))
            {
                try
                {
                    if (!GoogleValidatedAsync(model.Accesstoken, model.UserId).GetAwaiter().GetResult())
                    {
                        return Unauthorized("Unable to login with Google");
                    }
                }
                catch (Exception)
                {
                    return Unauthorized("Unable to login with Google");
                }

            }
            else
            {
                return BadRequest("Invalid provider");
            }

            var user = await _userManager.Users.FirstOrDefaultAsync(x => x.UserName == model.UserId && x.Provider==model.Provider);
            if (user == null) return Unauthorized("Unable to find your account");
            return CreateApplicationUserDto(user);

        }


        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto model)
        {
            if (await CheckEmailExistsAsync(model.Email))
            {
                return BadRequest($"An existing account is using {model.Email}, email adress. Please try with another");
            }

            var userToAdd = new User 
            { 
                FirstName = model.FirstName.ToLower(),
                LastName = model.LastName.ToLower(),
                UserName = model.Email.ToLower(),
                Email = model.Email.ToLower(),
                //EmailConfirmed=true
            };

            var result = await _userManager.CreateAsync(userToAdd,model.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            try
            {
                if(await sendConfirmEmailAsync(userToAdd))
                {
                    return Ok(new JsonResult(new {title="Account created", message="Your account has been created, please confirm your email address"}));
                }

                return BadRequest("Failed to send mail. Please contact admin");
            }
            catch(Exception)
            {
                return BadRequest("Failed to send mail. Please contact admin");
            }           

        }

        [HttpPost("register-with-third-party")]
        public async Task<ActionResult<UserDto>> RegisterWithThirdParty(RegisterWithExternalDto model)
        {
            if (model.Provider.Equals(SD.Facebook))
            {
                try
                {
                    if(!FacebookValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                    {
                        return Unauthorized("Unable to register with Facebook");
                    }
                }
                catch (Exception)
                {
                    return Unauthorized("Unable to register with Facebook");
                }

            }
            else if(model.Provider.Equals(SD.Google))
            {
                try
                {
                    if (!GoogleValidatedAsync(model.AccessToken, model.UserId).GetAwaiter().GetResult())
                    {
                        return Unauthorized("Unable to register with Google");
                    }  
                }
                catch (Exception)
                {
                    return Unauthorized("Unable to register with Google");
                }
            }
            else
            {
                return BadRequest("Invalid provider");
            }
           
            var user = await _userManager.FindByNameAsync(model.UserId);
            if (user != null) return BadRequest(string.Format("You have an account already. Please log in with your {0}", model.Provider));
            var userToADD = new User
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                UserName = model.UserId,
                Provider = model.Provider,
            };

            var result = await _userManager.CreateAsync(userToADD);
            if (!result.Succeeded) return BadRequest(result.Errors);

            return CreateApplicationUserDto(userToADD);
        }

        [HttpPut("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return Unauthorized("This email address has not been registered yet");
            if (user.EmailConfirmed == true) return BadRequest("Your email address was confirmed before. Please, log in to your account");
            try
            {
                var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);
                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

                if (result.Succeeded)
                {
                    return Ok(new JsonResult(new { title = "Email confirmed", message = "You email address is confirmed, you can log in now" }));
                }

                return BadRequest("Invalid token, please try again");
            }
            catch(Exception)
            {
                return BadRequest("Invalid token, please try again");
            }
        }

        [HttpPost("resend-email-confirmation-link/{email}")]
        public async Task <IActionResult> ResendEmailConfirmationLink(string email)
        {
            if(string.IsNullOrEmpty(email)) return BadRequest("Invalid email");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return Unauthorized("this email address has not been registered yet");
            if (user.EmailConfirmed == true) return BadRequest("Your email address was confirmed before. Please, log in to your account");

            try
            {
                if (await sendConfirmEmailAsync(user))
                {
                    return Ok(new JsonResult(new { title = "Confirmation link sent", message = "Please confirm your email address" }));
                }

                return BadRequest("Failed to send mail. Please contact admin");

            }
            catch (Exception)
            {
                return BadRequest("Failed to send mail. Please contact admin");
            }

        }

        [HttpPost("forgot-username-or-password/{email}")]
        public async Task<IActionResult> ForgotUsernameOrPassword(string email)
        {
            if (string.IsNullOrEmpty(email)) return BadRequest("Invalid email");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return Unauthorized("this email address has not been registered yet");

            if (user.EmailConfirmed == false) return BadRequest("Please confirm your email address first");

            try
            {
                if (await SendForgotUsernameOrPasswordEmail(user))
                {
                    return Ok(new JsonResult(new { title = "Forgot username or password sent", message = "Please check your mail" }));
                }

                return BadRequest("Failed to send mail. Please contact admin");

            }
            catch (Exception)
            {
                return BadRequest("Failed to send mail. Please contact admin");
            }

        }

        [HttpPut("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return Unauthorized("this email address has not been registered yet");

            if (user.EmailConfirmed == false) return BadRequest("Please confirm your email address first");

            try
            {
                var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);
                var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);

                if (result.Succeeded)
                {
                    return Ok(new JsonResult(new { title = "Password Reset success", message = "Your password has been reset" }));
                }

                return BadRequest("Invalid token, please try again");
            }
            catch (Exception)
            {
                return BadRequest("Invalid token, please try again");
            }
        }

        #region private helpers method
        private async Task<bool> SendForgotUsernameOrPasswordEmail(User user)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ResetPasswordPath"]}?token={token}&email={user.Email}";

            var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
                        $"<p>username: {user.UserName}</p>" +
                        "<p> in order to reset your password, please click on the following link</p>" +
                        $"<p><a href=\"{url}\">Click here</a></p>" +
                        "<p>Thank you</p>" +
                        $"<br>{_config["Email:ApplicationName"]}";

            var emailSend = new EmailSendDto(user.Email, "Forget password or username", body);

            return await _emailService.SendEmailAsynch(emailSend);
        }

        private UserDto CreateApplicationUserDto(User user)
        {

            return new UserDto
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                JWT = _jwtService.CreateJWT(user)
            };
        }

        private async Task<bool> sendConfirmEmailAsync(User user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var url = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

            var body = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
                "<p>Please confirm your Email address by clicking the following link</p>" +
                $"<p><a href=\"{url}\">Click here</a></p>" +
                "<p>Thank you</p>" +
                $"<br>{_config["Email:ApplicationName"]}";

            var emailSend = new EmailSendDto(user.Email, "Confirm your email", body);

            return await _emailService.SendEmailAsynch(emailSend);
        }

        private async Task<bool> CheckEmailExistsAsync(string email)
        {
            return await _userManager.Users.AnyAsync(x=> x.Email == email.ToLower());
        }

        public async Task<bool> FacebookValidatedAsync(string accessToken, string userId)
        {
            var facebookKeys = _config["Facebook:AppId"] + "|" + _config["Facebook:AppSecret"];
            var fbResult = await _facebookHttpClient.GetFromJsonAsync<FacebookResultDto>($"debug_token?input_token={accessToken}&access_token={facebookKeys}");

            if(fbResult == null || fbResult.Data.Is_Valid == false || !fbResult.Data.User_Id.Equals(userId) )
            {
                return false;
            }

            return true;
        }

        public async Task<bool> GoogleValidatedAsync(string accessToken, string userId)
        {
            var payLoad = await GoogleJsonWebSignature.ValidateAsync(accessToken);
            if (!payLoad.Audience.Equals(_config["Google:ClientId"]))
            {
                return false;
            }

            if(!payLoad.Issuer.Equals("accounts.google.com") && !payLoad.Issuer.Equals("https://accounts.google.com"))
            {
                return false;
            }

            if(payLoad.ExpirationTimeSeconds == null)
            {
                return false;
            }

            DateTime now = DateTime.Now.ToUniversalTime();
            DateTime expiration = DateTimeOffset.FromUnixTimeSeconds((long)payLoad.ExpirationTimeSeconds).DateTime;
            if(now > expiration)
            {
                return false;
            }

            if (!payLoad.Subject.Equals(userId))
            {
                return false;
            }

            return true;
        }

        #endregion
    }
}
