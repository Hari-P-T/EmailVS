using EmailAddressVerificationAPI.Services;
using EmailAddressVerificationAPI.Models;
using Service.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<SmtpValidator>();
builder.Services.AddSingleton<AliasUsernameCheck>();
builder.Services.AddSingleton<SpfCheck>();
builder.Services.AddSingleton<DmarckCkeck>();
builder.Services.AddSingleton<DkimCkeck>();
builder.Services.AddSingleton<GreyListedDomainsCheck>();
builder.Services.AddSingleton<DisposableDomainsCheck>();
builder.Services.AddSingleton<BlackListedDomainsCheck>();
builder.Services.AddSingleton<MXRecordChecker>();
builder.Services.AddSingleton<WhiteListedEmailProvider>();
builder.Services.AddSingleton<TopLevelDomainVerification>();
builder.Services.AddSingleton<VulgarWordSearch>();
builder.Services.AddSingleton<DisposableDomainsCheck>();
builder.Services.AddSingleton<DomainVerification>();
builder.Services.AddSingleton<ResponseDTO>();
builder.Services.AddSingleton<List<ChecklistElementDTO>>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseCors("AllowAll");
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthorization();

app.MapControllers();
app.Run();