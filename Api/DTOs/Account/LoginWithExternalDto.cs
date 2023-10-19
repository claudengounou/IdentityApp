using System.ComponentModel.DataAnnotations;

namespace Api.DTOs.Account
{
    public class LoginWithExternalDto
    {
        [Required]
        public string Accesstoken { get; set; }
        [Required]
        public string UserId { get; set; }
        [Required]
        public string Provider { get; set; }
    }
}
