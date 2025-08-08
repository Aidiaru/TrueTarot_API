using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Text;
using TrueTarot_API.Entities;
using TrueTarot_API.Infrastructure.Configuration;
using TrueTarot_API.Infrastructure.Data;
using TrueTarot_API.Infrastructure.Mapping;
using TrueTarot_API.Services;
using TrueTarot_API.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Database Configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// JWT Configuration
var jwtSettings = new JwtSettings();
builder.Configuration.GetSection("JwtSettings").Bind(jwtSettings);
builder.Services.AddSingleton(jwtSettings);

// Identity Configuration
builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false;
    
    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

// AutoMapper
builder.Services.AddAutoMapper(typeof(MappingProfile));

// Custom Services
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Swagger Configuration with JWT support
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "TrueTarot API",
        Version = "v1",
        Description = "TrueTarot WebAPI ile React frontend haberleþmesi için RESTful API",
        Contact = new OpenApiContact
        {
            Name = "TrueTarot Team"
        }
    });

    // JWT Authorization support in Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // XML Comments for documentation
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "TrueTarot API V1");
        c.RoutePrefix = string.Empty; // Swagger UI will be available at the app's root
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
