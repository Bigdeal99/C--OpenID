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

    // === Constants ===
    private const string clientId = "dotnet-client";
    private const string clientSecret = "TPREEXivXqxLBrnQ6czCQiEYkkhMBNXa";
    private const string redirectUri = "http://localhost:5226/callback";

    // === Config Fetch ===
    private async Task<OidcConfig> GetOidcConfig()
    {
        var client = new HttpClient();
        return await client.GetFromJsonAsync<OidcConfig>("http://localhost:8080/realms/master/.well-known/openid-configuration");
    }

    // === Views ===
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

    // === Login ===
    [HttpGet("/login")]
    public async Task<IActionResult> Login()
    {
        var config = await GetOidcConfig();

        // Generate PKCE verifier and challenge (URL-safe)
        var codeVerifierBytes = RandomNumberGenerator.GetBytes(32);
        var codeVerifier = Convert.ToBase64String(codeVerifierBytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var codeChallengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Convert.ToBase64String(codeChallengeBytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var state = Guid.NewGuid().ToString();

        HttpContext.Session.SetString("code_verifier", codeVerifier);
        HttpContext.Session.SetString("state", state);

        _logger.LogInformation("Redirecting to Keycloak with state: {State}", state);

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
[HttpPost("/logout")]
public IActionResult Logout()
{
    HttpContext.Session.Clear();
    return RedirectToAction("Index");
}

    // === Callback ===
    [HttpGet("/callback")]
    public async Task<IActionResult> Callback(string code, string state)
    {
        var storedState = HttpContext.Session.GetString("state");
        var codeVerifier = HttpContext.Session.GetString("code_verifier");

        if (state != storedState || string.IsNullOrEmpty(codeVerifier))
            return BadRequest("Invalid state or missing code verifier.");

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
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Token exchange failed: {Error}", responseBody);
            return BadRequest("Failed to exchange code for tokens. Error: " + responseBody);
        }

        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody);
        HttpContext.Session.SetString("access_token", tokenResponse.access_token);

        return RedirectToAction("Profile");
    }

    // === Profile ===
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
