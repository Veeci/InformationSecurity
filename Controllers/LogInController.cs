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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                TempData["Error"] = "Username or password is empty!";
                return RedirectToAction("Index");
            }

            byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
            var user = db.Users.ToList().SingleOrDefault(u => u.Username.SequenceEqual(usernameBytes));

            if (user != null)
            {
                byte[] salt = GetSaltFromStoredPassword(user.Password);
                byte[] hashedPassword = SHA256Hashing.HashPassword(password, salt);
                byte[] storedHashedPassword = GetHashedPasswordFromStoredPassword(user.Password);

                if (hashedPassword.SequenceEqual(storedHashedPassword))
                {
                    Session["Username"] = username;
                    Session["FullName"] = user.FullName; 

                    return View("Index");
                }
            }

            TempData["Error"] = "Invalid username or password!";
            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Signup(string username, string password, string confirmPassword, string fullName, string gender, string role, string department)
        {
            if (password != confirmPassword)
            {
                TempData["Error"] = "Passwords do not match!";
                return RedirectToAction("Index");
            }

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
                        Password = CombineSaltAndPassword(salt, hashedPassword),
                        FullName = fullName,
                        Gender = gender,
                        Role = role,
                        Department = department,
                        Image = ""
                    };

                    db.Users.Add(newUser);
                    db.SaveChanges();
                    TempData["Success"] = "Sign up successful!";
                    return RedirectToAction("Index");
                }
                return RedirectToAction("Index");
            }
            catch (Exception e)
            {
                TempData["Error"] = "There was an error: " + e.InnerException?.Message ?? e.Message;
                return RedirectToAction("Index");
            }
        }

        private byte[] CombineSaltAndPassword(byte[] salt, byte[] hashedPassword)
        {
            var combined = new byte[salt.Length + hashedPassword.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(hashedPassword, 0, combined, salt.Length, hashedPassword.Length);
            return combined;
        }

        private byte[] GetSaltFromStoredPassword(byte[] storedPassword)
        {
            var salt = new byte[16];
            Buffer.BlockCopy(storedPassword, 0, salt, 0, salt.Length);
            return salt;
        }

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