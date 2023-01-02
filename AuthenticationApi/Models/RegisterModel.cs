using System.ComponentModel.DataAnnotations;

namespace AuthenticationApi.Models
{
    public class RegisterModel
    {
        public int Id { get; set; }

        [Required, StringLength(100)]
        public string FullName { get; set; }

        [Required]
        public string Nickname { get; set; }

        [Required]
        public DateTime BirthDate { get; set; }

        [Required, StringLength(128)]
        public string Email { get; set; }

        [Required, StringLength(256)]
        public string Password { get; set; }

        [Required]
        public string PhoneNumber { get; set; }

        [Required]
        public bool Gender { get; set; }


        [Required]
        public int PIN { get; set; }


    }
}
