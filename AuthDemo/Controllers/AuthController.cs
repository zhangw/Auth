using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using AuthDemo.Filters;
using WebMatrix.WebData;

namespace AuthDemo.Controllers
{
    //[Authorize]
    [InitializeSimpleMembership]
    public class MyAccountController : Controller
    {
        //
        // GET: /Auth/
        [HttpPost]
        public ActionResult Auth()
        {
            var request = HttpContext.Request;
            var _userName = request.Params["userName"];
            var _license = request.Params["license"];
            if (_userName == null || _license == null)
            {
                return new JsonResult { JsonRequestBehavior = JsonRequestBehavior.AllowGet, Data = new { message = "LICENSE ERROR!" } };
            }
            else
            {
                var userName = _userName.ToString();
                var license = _license.ToString();
                if (WebSecurity.Login(userName, license, false))
                {
                    var application = HttpContext.ApplicationInstance.Application;

                    if (application.AllKeys.Contains(userName))
                    {
                        //some on has been authorized
                        return new JsonResult { JsonRequestBehavior = JsonRequestBehavior.AllowGet, Data = new { message = "FORBIDDEN!" } };
                    }
                    else
                    {
                        var ticket = Guid.NewGuid().ToString();
                        lock (application)
                        {
                            application.Add(userName, ticket);
                        }
                        HttpCookie cookie = null;
                        if (HttpContext.Response.Cookies["__ticket"] != null)
                        {
                            cookie = HttpContext.Response.Cookies["__ticket"];
                            cookie.Value = userName + "," + ticket;
                            cookie.HttpOnly = true;
                            HttpContext.Response.Cookies.Set(cookie);
                        }
                        else
                        {
                            cookie = new HttpCookie("__ticket");
                            cookie.Value = userName + "," + ticket;
                            cookie.HttpOnly = true;
                            HttpContext.Response.Cookies.Add(cookie);
                        }
                        return new JsonResult { JsonRequestBehavior = JsonRequestBehavior.AllowGet, Data = new { message = "AUTH OK!" } };
                    }
                }
                else
                {
                    return new JsonResult { JsonRequestBehavior = JsonRequestBehavior.AllowGet, Data = new { message = "LICENSE ERROR!" } };
                }
            }
        }

        //[ValidateAntiForgeryToken]
        [HttpPost]
        [MyAuthAttribute]
        public ActionResult GetEncryptData()
        {
            var cookies = HttpContext.Request.Cookies;
            for (int i = 0; i < cookies.Count; i++)
            {
                var cookie = cookies[i];
                HttpContext.Response.Write(string.Format("{0},{1},{2}\r\n", cookie.Name, cookie.Value, cookie.Path));
            }
            return null;
        }

        //[ValidateAntiForgeryToken]
        [HttpPost]
        [MyAuthAttribute]
        public ActionResult Logoff()
        {
            var application = HttpContext.ApplicationInstance.Application;
            var cookies = HttpContext.Request.Cookies;
            var userName = cookies["__ticket"].Value.Split(',')[0];
            if (application.AllKeys.Contains(userName))
            {
                lock (application)
                {
                    application.Remove(userName);
                }
            }
            return null;
        }
    }
}