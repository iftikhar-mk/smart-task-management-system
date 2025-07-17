using AuthService.Data;
using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Profiles;
using AuthService.Seeding;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Shared.Configs;
using System.Reflection;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


// Add services to the container.
builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

builder.Configuration.AddEnvironmentVariables();

builder.Services.AddAutoMapper(cfg =>
{
    cfg.AddProfile<AuthProfile>();
});

// Instead, we are using a shared SecretManager
builder.Services.AddSingleton<SecretManager>();
var secretManager = new SecretManager(builder.Configuration);

// Configuration Setup
builder.Services.AddSingleton<SecretManager>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<ITokenProvider, TokenProvider>();

// Database Connection - Using SecretManager to get connection string
var authDbConnectionString = secretManager.GetSecret(AzureSecrets.AuthDbConnectionString);

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(authDbConnectionString));

// Azure Secrets for Identity
var jwtKey = secretManager.GetSecret(AzureSecrets.JwtKey);
var issuer = secretManager.GetSecret(AzureSecrets.JwtIssuer);
var audience = secretManager.GetSecret(AzureSecrets.JwtAudience);

// Add JWT Bearer Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddGoogle(google =>
    {
        google.ClientId = secretManager.GetSecret(AzureSecrets.GoogleClientId) ?? "";
        google.ClientSecret = secretManager.GetSecret(AzureSecrets.GoogleClientSecret) ?? "";
    })
.AddMicrosoftAccount(microsoft =>
{
    microsoft.ClientId = secretManager.GetSecret(AzureSecrets.MicrosoftClientId) ?? "";
    microsoft.ClientSecret = secretManager.GetSecret(AzureSecrets.MicrosoftClientSecret) ?? "";
})
.AddGitHub(github =>
{
    github.ClientId = secretManager.GetSecret(AzureSecrets.GitHubClientId) ?? "";
    github.ClientSecret = secretManager.GetSecret(AzureSecrets.GitHubClientSecret) ?? "";
})
.AddFacebook(facebook =>
{
    facebook.AppId = secretManager.GetSecret(AzureSecrets.FacebookClientId) ?? "";
    facebook.AppSecret = secretManager.GetSecret(AzureSecrets.FacebookClientSecret) ?? "";
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        RequireExpirationTime = true,
        ValidateActor = true,

        ValidIssuer = secretManager.GetSecret(AzureSecrets.JwtIssuer),
        ValidAudience = secretManager.GetSecret(AzureSecrets.JwtAudience),
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(secretManager.GetSecret(AzureSecrets.JwtKey)))
    };

    // ADD THIS SECTION RIGHT HERE:
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine("Token validated successfully.");
            return Task.CompletedTask;
        },
        // For even more detailed debugging:
        OnMessageReceived = context =>
        {
            Console.WriteLine($"Received token: {context.Token}");
            return Task.CompletedTask;
        }
    };
});


builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.AddSecurityDefinition(name: "Bearer", securityScheme: new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Bearer Token is required. Please use the format `Bearer JWT-KEY-VALUE`",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    var securityScheme = new OpenApiSecurityScheme
    {
        Reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = JwtBearerDefaults.AuthenticationScheme
        }
    };

    option.AddSecurityRequirement(new OpenApiSecurityRequirement { [securityScheme] = Array.Empty<string>() });

    // Optional: Include XML comments if you want Swagger to show summaries and examples
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        option.IncludeXmlComments(xmlPath);
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    if (ApplyMigration())
    {
        using (var scope = app.Services.CreateScope())
        {
            await RoleSeeder.SeedAsync(scope.ServiceProvider);
        }
    }

    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService API v1");
        options.RoutePrefix = "swagger";
    });
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();


// Custom method to auto run update-database when migration is added. 
bool ApplyMigration()
{
    try
    {
        using (var scope = app.Services.CreateScope())
        {
            var _db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            if (_db != null && _db.Database.GetPendingMigrations().Count() > 0)
            {
                _db.Database.Migrate();
            }
        }

        return true;
    }
    catch (Exception)
    {
        return false;
    }
}