using CustomerAPI.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace CustomerAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);


            // Add services to the container.
            builder.Services.AddControllers();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();

            // Connection string
            builder.Services.AddDbContext<AdminDBContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("cnString"));
            });

            var _dbcontext = builder.Services.BuildServiceProvider().GetService<AdminDBContext>();
            // Refresh Token
            builder.Services.AddSingleton<IRefreshTokenGenerator>(provider => new RefreshTokenGenerator(_dbcontext!));

            //JWTSetting Setting
            var _jwtsetting = builder.Configuration.GetSection("JWTSetting");
            builder.Services.Configure<JWTSetting>(_jwtsetting);

            // Authentication
            var authKey = builder.Configuration.GetValue<string>("JWTSetting:securitykey");
            builder.Services.AddAuthentication(item =>
            {
                item.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                item.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(item =>
            {
                item.RequireHttpsMetadata = true;
                item.SaveToken = true;
                item.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authKey)),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });

            // Swagger
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("api", new OpenApiInfo()
                {
                    Description = "Customer API with curd operaitons",
                    Title = "Customer",
                    Version = "v1",
                });
            });
            

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            //if (app.Environment.IsDevelopment())
            //{
            //    app.UseSwagger();
            //    app.UseSwaggerUI(options => options.SwaggerEndpoint("api/swagger.json", "Customer"));
            //}
            app.UseSwagger();
            app.UseSwaggerUI(options => options.SwaggerEndpoint("api/swagger.json", "Customer"));

            // CORS
            app.UseCors(builder =>
            {
                builder
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader();
            });

            app.UseHttpsRedirection();

            // Authentication
            app.UseAuthentication();

            // Authorization
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}