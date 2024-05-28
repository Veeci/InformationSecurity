namespace EmployeeManagementWebsite.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Admin")]
    public partial class Admin
    {
        public int AdminID { get; set; }

        [Required]
        [MaxLength(260)]
        public byte[] Username { get; set; }

        [Required]
        public byte[] Password { get; set; }

        [Required]
        [StringLength(256)]
        public string FullName { get; set; }
    }
}
