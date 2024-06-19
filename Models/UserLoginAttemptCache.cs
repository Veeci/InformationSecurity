using System.Collections.Concurrent;

namespace EmployeeManagementWebsite.Models
{
    public static class UserLoginAttemptCache
    {
        private static readonly ConcurrentDictionary<string, UserLoginAttempt> Attempts = new ConcurrentDictionary<string, UserLoginAttempt>();

        public static UserLoginAttempt GetOrCreate(string username)
        {
            return Attempts.GetOrAdd(username, _ => new UserLoginAttempt { Username = username, FailedAttempts = 0 });
        }

        public static void Reset(string username)
        {
            Attempts.TryRemove(username, out _);
        }
    }
}