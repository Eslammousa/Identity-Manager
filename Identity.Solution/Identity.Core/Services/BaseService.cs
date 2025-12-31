using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.Services
{
    public class BaseService
    {
        protected readonly IHttpContextAccessor _httpContextAccessor;

        public BaseService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected Guid GetCurrentUserId()
        {
            var userId = _httpContextAccessor.HttpContext?
                .User
                .FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
                throw new UnauthorizedAccessException("User is not authenticated");

            return Guid.Parse(userId);
        }
    }
}
