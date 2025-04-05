using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using OidcClientApp.Models;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.WebUtilities;


namespace OidcClientApp.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }
private async Task<OidcConfig> GetOidcConfig()
{
    var client = new HttpClient();
    return await client.GetFromJsonAsync<OidcConfig>("http://localhost:8080/realms/master/.well-known/openid-configuration");
}
private const string clientId = "dotnet-client";
private const string clientSecret = "<TPREEXivXqxLBrnQ6czCQiEYkkhMBNXa>";
private const string redirectUri = "https://localhost:5001/callback";

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
    [HttpGet("/login")]
public async Task<IActionResult> Login()
{
    var config = await GetOidcConfig();

    // Generate PKCE code verifier and challenge
    var codeVerifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    var codeChallenge = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier)))
        .Replace("+", "-").Replace("/", "_").Replace("=", "");

    var state = Guid.NewGuid().ToString();
    HttpContext.Session.SetString("code_verifier", codeVerifier);
    HttpContext.Session.SetString("state", state);

    var parameters = new Dictionary<string, string?>
    {
        { "client_id", clientId },
        { "scope", "openid email profile" },
        { "response_type", "code" },
        { "redirect_uri", redirectUri },
        { "state", state },
        { "code_challenge_method", "S256" },
        { "code_challenge", codeChallenge },
        { "prompt", "login" }
    };

    var authorizationUrl = QueryHelpers.AddQueryString(config.authorization_endpoint, parameters);
    return Redirect(authorizationUrl);
}
[HttpGet("/callback")]
public async Task<IActionResult> Callback(string code, string state)
{
    var storedState = HttpContext.Session.GetString("state");
    var codeVerifier = HttpContext.Session.GetString("code_verifier");

    if (state != storedState || string.IsNullOrEmpty(codeVerifier))
        return BadRequest("Invalid state or missing verifier.");

    var config = await GetOidcConfig();

    var parameters = new Dictionary<string, string?>
    {
        { "grant_type", "authorization_code" },
        { "code", code },
        { "redirect_uri", redirectUri },
        { "client_id", clientId },
        { "client_secret", clientSecret },
        { "code_verifier", codeVerifier }
    };

    var http = new HttpClient();
    var response = await http.PostAsync(config.token_endpoint, new FormUrlEncodedContent(parameters));

    if (!response.IsSuccessStatusCode)
        return BadRequest("Failed to exchange code for tokens");

    var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

    // Store access token in session
    HttpContext.Session.SetString("access_token", tokenResponse.access_token);

    return RedirectToAction("Profile");
}
[HttpGet("/profile")]
public async Task<IActionResult> Profile()
{
    var accessToken = HttpContext.Session.GetString("access_token");
    if (string.IsNullOrEmpty(accessToken))
        return Redirect("/");

    var config = await GetOidcConfig();

    var http = new HttpClient();
    http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

    var response = await http.GetAsync(config.userinfo_endpoint);
    var userInfo = await response.Content.ReadAsStringAsync();

    ViewBag.UserInfo = JsonDocument.Parse(userInfo).RootElement;
    return View();
}

}
