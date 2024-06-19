using System;

namespace EmployeeManagementWebsite.Models
{
    public class UserLoginAttempt
    {
        public string Username { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockoutEnd { get; set; }
    }
}