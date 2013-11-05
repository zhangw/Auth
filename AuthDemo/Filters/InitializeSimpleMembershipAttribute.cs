using System;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Web.Mvc;
using AuthDemo.Models;
using WebMatrix.WebData;

namespace AuthDemo.Filters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public sealed class InitializeSimpleMembershipAttribute : ActionFilterAttribute
    {
        private static SimpleMembershipInitializer _initializer;
        private static object _initializerLock = new object();
        private static bool _isInitialized;

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            // Ensure ASP.NET Simple Membership is initialized only once per app start
            LazyInitializer.EnsureInitialized(ref _initializer, ref _isInitialized, ref _initializerLock);
        }

        private class SimpleMembershipInitializer
        {
            public SimpleMembershipInitializer()
            {
                Database.SetInitializer<UsersContext>(null);

                try
                {
                    using (var context = new UsersContext())
                    {
                        if (!context.Database.Exists())
                        {
                            // Create the SimpleMembership database without Entity Framework migration schema
                            ((IObjectContextAdapter)context).ObjectContext.CreateDatabase();
                        }
                    }
                    WebSecurity.InitializeDatabaseConnection("DefaultConnection", "UserProfile", "UserId", "UserName", autoCreateTables: true);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("The ASP.NET Simple Membership database could not be initialized. For more information, please see http://go.microsoft.com/fwlink/?LinkId=256588", ex);
                }
            }
        }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class MyAuthAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            var cookies = filterContext.HttpContext.Request.Cookies;
            var __ticket = cookies["__ticket"];
            var result = true;
            if (__ticket != null && !string.IsNullOrEmpty(__ticket.Value))
            {
                string[] values = __ticket.Value.Split(',');
                if (values.Length != 2)
                {
                    //failure
                    result = false;
                }
                else
                {
                    var application = filterContext.HttpContext.ApplicationInstance.Application;
                    var userName = values[0];
                    var ticket = values[1];
                    if (application[userName] != null && application[userName].ToString() == ticket)
                    {
                        //ok
                        //filterContext.HttpContext.Response.Write("YOU HAVE THE PERMISSION TO GET DATA!");
                    }
                    else
                    {
                        //failure
                        result = false;
                    }
                }
            }
            else
            {
                //failure
                result = false;
            }
            if (!result)
            {
                filterContext.HttpContext.Response.Cookies.Remove("__ticket");
                filterContext.Result = new JsonResult { JsonRequestBehavior = JsonRequestBehavior.AllowGet, Data = new { message = "AUTH ERROR!" } };
            }
        }
    }
}