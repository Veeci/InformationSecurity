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
            return View(db.Users.ToList());
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

            try
            {
                //Băm username mà người dùng nhập vào khi đăng nhập
                byte[] hashedUsername = SHA256Hashing.Hash(username);

                //Lấy danh sách các username đã băm trong db, so sánh với username đã băm ở trên
                var user = db.Users.ToList().SingleOrDefault(u => hashedUsername.SequenceEqual(u.Username));

                //nếu có tồn tại user nào có username trùng với username được nhập vào 
                if (user != null)
                {
                    //Tiến hành băm tiếp mật khẩu được người dùng nhập vào
                    byte[] hashedPassword = SHA256Hashing.Hash(password);

                    //So sánh bản băm mật khẩu đó với mật khẩu của người dùng đã được băm trong db
                    if (hashedPassword.SequenceEqual(user.Password))
                    {
                        Session["Username"] = username; //Lưu username vào session
                        Session["FullName"] = user.FullName; //Lưu họ tên của use vào session

                        return View("Index");
                    }
                    else
                    {
                        // Trường hợp mật khẩu được nhập vào không trùng với mật khẩu trong db
                        TempData["Error"] = "Password mismatch!";
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
                    // Băm username và password
                    byte[] hashedUsername = SHA256Hashing.Hash(username);
                    byte[] hashedPassword = SHA256Hashing.Hash(password);

                    User newUser = new User
                    {
                        Username = hashedUsername,
                        Password = hashedPassword,
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
                TempData["Error"] = "There was an error: " + (e.InnerException?.Message ?? e.Message);
                return RedirectToAction("Index");
            }
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
/*
    Sau khi đăng ký, tài khoản và mật khẩu sau khi băm sẽ được lưu vào csdl
    Khi check trong csdl, tài khoản mật khẩu được lưu có 66 ký tự
    Lí do: đầu ra của SHA-256 mặc định có 256 bit, tương ứng với 32 byte = 64 ký tự 16 bit
    Thêm 2 ký tự 0x ở đầu mặc định được thêm vào do các ký tự đầu ra là hệ hex
 */