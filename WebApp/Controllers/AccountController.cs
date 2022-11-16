using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using WebApp.Models;

namespace WebApp.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private ApplicationDbContext db = ApplicationDbContext.Create();

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ActionResult Index()
        {
            ViewBag.Users = db.Users;
            return View();
        }

        public ActionResult Change(string option, string[] selected)
        {
            if (selected != null)
            {
                switch (option)
                {
                    case "d":
                        Delete(selected);
                        break;
                    case "b":
                        Block(selected);
                        break;
                    case "u":
                        Unblock(selected);
                        break;
                }
            }
            return RedirectToAction("Index");
        }

        private void Delete(string[] selected)
        {
            for (int i = 0; i < selected.Length; i++)
            {
                db.Users.Remove(db.Users.Find(selected[i]));
            }
            db.SaveChanges();
        }

        private void Block(string[] selected)
        {
            for (int i = 0; i < selected.Length; i++)
            {
                ApplicationUser user = db.Users.Find(selected[i]);
                user.LockoutEndDateUtc = DateTime.Now.AddYears(100);
                UserManager.UpdateSecurityStamp(user.Id);
                user.Status = "Заблокирован";
            }
            db.SaveChanges();
        }

        private void Unblock(string[] selected)
        {
            for (int i = 0; i < selected.Length; i++)
            {
                ApplicationUser user = db.Users.Find(selected[i]);
                user.LockoutEndDateUtc = null;
                if (user.Status == "Заблокирован") user.Status = "Не в сети";
            }
            db.SaveChanges();
        }

        [AllowAnonymous]
        public ActionResult Login()
        {
            if (Request.IsAuthenticated)
            {
                return RedirectToAction ("Index");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            ApplicationUser user = UserManager.FindByEmail(model.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Пользователя с таким адресом не существует.");
                return View(model);
            }

            var result = await SignInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    ApplicationUser currentUser = db.Users.Find(user.Id);
                    currentUser.LastLogin = DateTime.Now;
                    currentUser.Status = "В сети";
                    db.SaveChanges();
                    return RedirectToAction("Index");
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Неудачная попытка входа.");
                    return View(model);
            }
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            if (Request.IsAuthenticated)
            {
                return RedirectToAction("Index");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.UserName, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent:false, rememberBrowser:false);
                    return RedirectToAction("Index", "Account");
                }
                AddErrors(result);
            }
            return View(model);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            db.Users.Find(User.Identity.GetUserId()).Status = "Не в сети";
            db.SaveChanges();
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Login", "Account");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Вспомогательные приложения

        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}