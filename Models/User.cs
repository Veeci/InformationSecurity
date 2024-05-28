namespace EmployeeManagementWebsite.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("User")]
    public partial class User
    {
        public int UserID { get; set; }

        [Required]
        [MaxLength(260)]
        public byte[] Username { get; set; }

        [Required]
        public byte[] Password { get; set; }

        [Required]
        [StringLength(256)]
        public string FullName { get; set; }

        [StringLength(10)]
        public string Gender { get; set; }

        [StringLength(256)]
        public string Image { get; set; }

        [Required]
        [StringLength(256)]
        public string Role { get; set; }

        [Required]
        [StringLength(256)]
        public string Department { get; set; }
    }
}
