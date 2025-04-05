namespace OidcClientApp.Models;

public class OidcConfig
{
    public string authorization_endpoint { get; set; }
    public string token_endpoint { get; set; }
    public string userinfo_endpoint { get; set; }
    public string jwks_uri { get; set; }
}
