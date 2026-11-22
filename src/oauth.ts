
type OAuthConfig = {
  id: string;
  secret: string;
  target: {
    tokenHost: string;
    tokenPath: string;
    authorizePath: string;
  };
};

export class OAuthClient {
  private clientConfig: OAuthConfig;

  constructor(config: OAuthConfig) {
    this.clientConfig = config;
  }

  authorizeURL(options: {
    redirect_uri: string;
    scope: string;
    state: string;
  }): string {
    const { tokenHost, authorizePath } = this.clientConfig;

    const url = new URL(authorizePath, tokenHost);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientConfig.id);
    url.searchParams.set("redirect_uri", options.redirect_uri);
    url.searchParams.set("scope", options.scope);
    url.searchParams.set("state", options.state);

    return url.toString();
  }

  async getToken(options: {
    code: string;
    redirect_uri: string;
  }): Promise<string> {
    const { tokenHost, tokenPath } = this.clientConfig;

    const response = await fetch(
      new URL(tokenPath, tokenHost).toString(),
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: this.clientConfig.id,
          client_secret: this.clientConfig.secret,
          code: options.code,
          redirect_uri: options.redirect_uri,
        }),
      }
    );

    if (!response.ok) {
      throw new Error("GitHub token request failed");
    }

    const data: unknown = await response.json();

    if (
      typeof data !== "object" ||
      data === null ||
      !("access_token" in data) ||
      typeof data.access_token !== "string" ||
      !data.access_token
    ) {
      throw new Error("GitHub did not return a valid access token");
    }

    return data.access_token;
  }
}
