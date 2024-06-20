using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using EmployeeManagementWebsite.Models;

namespace EmployeeManagementWebsite.Controllers
{
    public class AdminsController : Controller
    {
        private Model1 db = new Model1();

        // GET: Admins
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult EmployeeList()
        {
            return View(db.Users.ToList());
        }

        // GET: Login
        public ActionResult Login()
        {
            return View();
        }

        // POST: Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                TempData["Error"] = "Username or password is empty!";
                return View();
            }

            try
            {
                byte[] hashedUsername = SHA256Hashing.Hash(username);
                var admin = db.Admins.AsEnumerable().SingleOrDefault(u => hashedUsername.SequenceEqual(u.Username));

                if (admin != null)
                {
                    var attempt = UserLoginAttemptCache.GetOrCreate(username);

                    if (attempt.LockoutEnd.HasValue && DateTime.Now < attempt.LockoutEnd.Value)
                    {
                        TempData["Error"] = "Account is locked. Please try again later.";
                        return View();
                    }

                    byte[] hashedPassword = SHA256Hashing.Hash(password);

                    if (hashedPassword.SequenceEqual(admin.Password))
                    {
                        Session["admin"] = username;
                        Session["admin"] = admin.FullName;

                        UserLoginAttemptCache.Reset(username);

                        return RedirectToAction("Index", "Admins");
                    }
                    else
                    {
                        attempt.FailedAttempts++;
                        if (attempt.FailedAttempts >= 5)
                        {
                            attempt.LockoutEnd = DateTime.Now.AddMinutes(15);
                            TempData["Error"] = "Account locked due to multiple failed login attempts.";
                        }
                        else
                        {
                            TempData["Error"] = "Password mismatch!";
                        }
                    }
                }
                else
                {
                    TempData["Error"] = "Username not found!";
                }
            }
            catch (Exception ex)
            {
                TempData["Error"] = "An unexpected error occurred: " + ex.Message;
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            Session.Clear();
            return RedirectToAction("Index");
        }

        // GET: Admins/Details/5
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

        // GET: Admins/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Admins/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "AdminID,Username,Password,FullName")] Admin admin)
        {
            if (ModelState.IsValid)
            {
                db.Admins.Add(admin);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(admin);
        }

        // GET: Admins/Delete/5
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

        // POST: Admins/Delete/5
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