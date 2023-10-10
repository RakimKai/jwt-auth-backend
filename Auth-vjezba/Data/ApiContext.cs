using Microsoft.EntityFrameworkCore;
using Auth_vjezba.Models;
namespace Auth_vjezba.Data
{
    public class ApiContext : DbContext
    {
        public DbSet<Users> Users { get; set; }
       

        public ApiContext(DbContextOptions<ApiContext> options) :base(options) 
        { 
        
        }
            
    }
}
