using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Linq;
using System.Security.Claims;

namespace WebApplication9.Controllers
{
    [AttributeUsage(AttributeTargets.All, AllowMultiple = false, Inherited = true)]
    public class ClaimAuthorization : AuthorizeAttribute, IAuthorizationFilter
    {
        private string _claim;
        private string[] _claims = new string[0];
        public string Claims
        {
            get { return _claim ?? string.Empty; }
            set
            {
                _claim = value;
                _claims = SplitClaims(value);
            }
        }
        private string _microsoftClaimsUrl = string.Empty;//CommonMethods.ReadValueFromServiceFabricSettings("Config", "Security", "MicrosoftClaimsUrl");

        public const string clientAid = "client_aid";
        public const string scope = "scope";
        public const string tid = "tid";
        public const string tenantIdKey = "tenantId";
        public const string client = "client_";
        public const string preferred_user = "role";

        private static string[] SplitClaims(string inputClaims)
        {
            if (string.IsNullOrEmpty(inputClaims))
            {
                return new string[0];
            }

            var split = from piece in inputClaims.Split(',')
                        let trimmed = piece.Trim()
                        where !string.IsNullOrEmpty(trimmed)
                        select trimmed;
            return split.ToArray();
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            //TenantId from current HttpActionContext
            string _ctxTenantId = string.Empty;
            //TenantId from Claims
            string _claimTenantId = string.Empty;

            bool isAuthorized = false;
            //Gets the claimprincipal from current HttpActionContext
            var principal = context.HttpContext.User;

            if (principal == null || !principal.Identity.IsAuthenticated)
            {
                context.Result = new UnauthorizedResult();
                return;
            }
            //if no role based authorization required for specific controller action
            if (_claims.Count() == 0)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            if (principal.Claims.Where(m => m.Type == _microsoftClaimsUrl).Count() > 0)
            {
                ImplicitAuthenticationFlow(context, ref _ctxTenantId, ref _claimTenantId, isAuthorized, principal);
            }
            else
            {
                ClientCredentialAuthenticationFlow(context, ref _ctxTenantId, ref _claimTenantId, isAuthorized, principal);
            }

        }

        private void ImplicitAuthenticationFlow(
            AuthorizationFilterContext context,
            ref string _ctxTenantId,
            ref string _claimTenantId,
            bool isAuthorized,
            ClaimsPrincipal principal)
        {
            //Extract the claims available in claimprincipal
            var roleClaim = principal.Claims.Where(m => m.Type == _microsoftClaimsUrl);
            foreach (var claim in _claims)
            {
                //if roles in claims matches role required to access specific controller action then return true
                if (roleClaim.Any(x => string.Compare(x.Value, claim, false) == 0))
                {
                    return;
                }
            }
            context.Result = new UnauthorizedResult();
            return;
        }

        private void ClientCredentialAuthenticationFlow(
            AuthorizationFilterContext actionContext,
            ref string _ctxTenantId, ref string _claimTenantId,
            bool isAuthorized, ClaimsPrincipal principal)
        {

            if (principal == null || !principal.Identity.IsAuthenticated)
            {
                actionContext.Result = new UnauthorizedResult();
                return;
            }
            //if no role based authorization required for specific controller action
            if (_claims.Count() == 0)
            {
                actionContext.Result = new UnauthorizedResult();
                return;
            }

            //Verifies for authentication
            var permissionClaim = principal.Claims.Where(m => m.Type == client + _microsoftClaimsUrl);
            foreach (var claim in _claims)
            {
                //if roles in claims matches role required to access specific controller action then return true
                if (permissionClaim.Any(x => string.Compare(x.Value, claim, false) == 0))
                {
                    return;
                }
            }
            actionContext.Result = new UnauthorizedResult();
            return;
        }
    }
}
