using System;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Text;
using System.Web.Mvc;
using EmployeeManagementWebsite.Models;

namespace EmployeeManagementWebsite.Controllers
{
    public class LogInController : Controller
    {
        private Model1 db = new Model1();

        // GET: LogIn
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult EmployeeList()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                ViewBag.Error = "Username or password is empty!";
                return View("Login");
            }

            // Convert username to byte array
            var usernameBytes = Encoding.UTF8.GetBytes(username);

            // Fetch the user from the database
            var user = db.Users.FirstOrDefault(u => u.Username == usernameBytes);

            if (user != null)
            {
                // Check if the hashed password matches the stored password
                byte[] salt = GetSaltFromStoredPassword(user.Password);
                byte[] hashedPassword = SHA256Hashing.HashPassword(password, salt);
                byte[] storedHashedPassword = GetHashedPasswordFromStoredPassword(user.Password);

                if (hashedPassword.SequenceEqual(storedHashedPassword))
                {
                    // Store the username in the session
                    Session["Username"] = username;

                    // Generate a session token
                    string sessionToken = GenerateSessionToken(username);

                    // Store the session token in session or database
                    Session["SessionToken"] = sessionToken;

                    // Authentication successful
                    return RedirectToAction("Index", "Home");
                }
            }

            ViewBag.Error = "Invalid username or password!";
            return View("Login");
        }

        private string GenerateSessionToken(string username)
        {
            // Combine username with a secret key
            string secretKey = "your_secret_key_here";
            string combined = username + secretKey;

            // Calculate SHA-256 hash
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                // Convert hash to string (hexadecimal representation)
                return BitConverter.ToString(hashBytes).Replace("-", "");
            }
        }

        [HttpGet]
        public ActionResult Logout()
        {
            // Invalidate the session token
            Session.Remove("SessionToken");
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public ActionResult Signup()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Signup(string username, string password)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    byte[] salt = SHA256Hashing.GenerateSalt();
                    byte[] hashedPassword = SHA256Hashing.HashPassword(password, salt);
                    byte[] usernameBytes = Encoding.UTF8.GetBytes(username);

                    User newUser = new User
                    {
                        Username = usernameBytes,
                        Password = CombineSaltAndPassword(salt, hashedPassword)
                    };

                    db.Users.Add(newUser);
                    db.SaveChanges();
                    return RedirectToAction("Login", "Login");
                }
                return View();
            }
            catch (Exception e)
            {
                ViewBag.Error = "There was an error: " + e.Message;
                return View();
            }
        }

        // Utility method to combine salt and password
        private byte[] CombineSaltAndPassword(byte[] salt, byte[] hashedPassword)
        {
            var combined = new byte[salt.Length + hashedPassword.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(hashedPassword, 0, combined, salt.Length, hashedPassword.Length);
            return combined;
        }

        // Utility method to extract salt from stored password
        private byte[] GetSaltFromStoredPassword(byte[] storedPassword)
        {
            var salt = new byte[16];
            Buffer.BlockCopy(storedPassword, 0, salt, 0, salt.Length);
            return salt;
        }

        // Utility method to extract hashed password from stored password
        private byte[] GetHashedPasswordFromStoredPassword(byte[] storedPassword)
        {
            var hashedPassword = new byte[storedPassword.Length - 16];
            Buffer.BlockCopy(storedPassword, 16, hashedPassword, 0, hashedPassword.Length);
            return hashedPassword;
        }

        // GET: LogIn/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // GET: LogIn/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: LogIn/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "UserID,Username,Password,FullName,Gender,Image,Role,Department")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Users.Add(user);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(user);
        }

        // GET: LogIn/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: LogIn/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "UserID,Username,Password,FullName,Gender,Image,Role,Department")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(user);
        }

        // GET: LogIn/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: LogIn/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
