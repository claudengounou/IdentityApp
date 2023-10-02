using Api.Data;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<Context>(options => 
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

//to be able to ijenct our jwtservice inside our controllers
builder.Services.AddScoped<JWTService>();

//defining our IdentityCore service
builder.Services.AddIdentityCore<User>(options =>
{
    //password configuration
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;

    //email confirmation
    options.SignIn.RequireConfirmedEmail = true;   
    })
    .AddRoles<IdentityRole>() //to be able to add roles
    .AddRoleManager<RoleManager<IdentityRole>>() // to be able to make use of rolemanager to create role
    .AddEntityFrameworkStores<Context>() // providing our Context
    .AddSignInManager<SignInManager<User>>() // make use of SignInManager in order to sign User in
    .AddUserManager<UserManager<User>>() //make use of UserManager in order to create User
    .AddDefaultTokenProviders(); //to be able to create tokens for email confirmation

//to be able to authenticate users with JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
           //validate the token based on the key we have provided in appsettings.Development.json JWT:key
            ValidateIssuerSigningKey = true,
            //the Issuer signin key based on JWT:key
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
            //the Issuer which is here is the api project url we are using
            ValidIssuer = builder.Configuration["JWT:Issuer"],
            //validate the issuer(who ever is issuing the jwt)
            ValidateIssuer = true,
            //dont validate audience(angular side)
            ValidateAudience = false
        };
    });

builder.Services.AddCors();

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = actionContext =>
    {
        var errors = actionContext.ModelState
        .Where(x => x.Value.Errors.Count() > 0)
        .SelectMany(x => x.Value.Errors)
        .Select(x => x.ErrorMessage).ToArray();

        var toReturn = new
        {
            Errors = errors
        };

        return new BadRequestObjectResult(toReturn);
    };
});

var app = builder.Build();

app.UseCors(opt =>
    {
    opt.AllowAnyHeader().AllowAnyMethod().AllowCredentials().WithOrigins(builder.Configuration["JWT:ClientUrl"]);
    });

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//add useAuthentication tou our pipeline and this should come before useAuthorization
//authentication verifies the identity of a user or service, and authorization determines their access rights
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
