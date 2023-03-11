export default class Authorize {
  authUrl: string;
  authCookieName: string;

  constructor(options: { authUrl: string; authCookieName?: string }) {
    this.authUrl = options.authUrl;
    this.authCookieName = options.authCookieName || "authToken";
  }

  async authorizeByToken(token: string) {
    return Authorize.authByToken(this.authUrl + "/token", token);
  }
  async checkLogin(token?: string) {
    return Authorize.checkLogin(
      this.authUrl + "/token",
      this.authCookieName,
      token
    );
  }
  async authorizeSocialLogin(detail: {
    token: string;
    provider: string;
    redirect_uri: string;
  }) {
    return Authorize.authorizeSocialLogin(detail, {
      authUrl: this.authUrl,
      authCookieName: this.authCookieName,
    });
  }
  async socialLoginOauthAnswer(detail: {
    token?: string;
    provider: string;
    tmpCode?: string;
    redirect_uri?: string;
  }) {
    return Authorize.socialLoginOauthAnswer(detail, {
      authUrl: this.authUrl,
      authCookieName: this.authCookieName,
    });
  }

  static async authByToken(tokenUri: string, token: string) {
    const auth = await fetch(tokenUri, {
      headers: { Authorization: token, "Content-Type": "application/json" },
      method: "POST",
      body: JSON.stringify({ token: token }),
    });
    if (auth.ok) {
      const decodedAuth: { token: string; error?: any; _id: string } =
        await auth.json();
      if (decodedAuth.error) {
        throw new Error("unauthorized");
      } else if (!decodedAuth.token) {
        console.error("no token on answer");

        throw new Error("no token on answer");
      } else {
        return decodedAuth.token;
      }
    } else {
      throw new Error("unauthorized");
    }
  }
  static async checkLogin(
    tokenUri: string,
    authCookieName: string,
    token?: string
  ) {
    if (!authCookieName) throw new Error("authCookieName is not defined");
    if (!tokenUri) throw new Error("tokenUri is not defined");
    let storageType = "localStorage";
    let tk: string;
    tk = localStorage.getItem(authCookieName) as string;
    if (!tk) {
      tk = sessionStorage.getItem(authCookieName) as string;
      storageType = "sessionStorage";
    }
    if (token) {
      console.info("checking auth by token");

      try {
        const newToken = await Authorize.authByToken(tokenUri, token);
        console.info("new token token", newToken);

        switch (storageType) {
          case "localStorage":
            localStorage.setItem(authCookieName, newToken);
            break;
          case "sessionStorage":
            sessionStorage.setItem(authCookieName, newToken);
            break;
        }

        return newToken;
      } catch (err) {
        throw new Error("token is not valid");
      }
    }

    if (tk) {
      console.info("checking local token", tk);
      try {
        const newToken = await Authorize.authByToken(tokenUri, tk);
        console.info("new token token", newToken);

        switch (storageType) {
          case "localStorage":
            localStorage.setItem(authCookieName, newToken);
            break;
          case "sessionStorage":
            sessionStorage.setItem(authCookieName, newToken);
            break;
        }

        return newToken;
      } catch (err) {
        console.error("error on authByToken", err);

        console.error("not logged");
        switch (storageType) {
          case "localStorage":
            localStorage.removeItem(authCookieName);
            break;
          case "sessionStorage":
            sessionStorage.removeItem(authCookieName);
            break;
        }
        throw new Error("not logged");
      }
    } else {
      throw new Error("not authorized");
    }
  }

  static async authorizeSocialLogin(
    detail: {
      token: string;
      provider: string;
      redirect_uri: string;
    },
    options: { authUrl: string; authCookieName?: string }
  ) {
    const url = options.authUrl + "/social/login";
    const response = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      method: "POST",
      body: JSON.stringify(
        Object.assign({ redirect_uri: detail.redirect_uri }, detail)
      ),
    });
    console.log("server answer with", response);
    if (response.ok) {
      const data = await response.json();

      if (options.authCookieName)
        localStorage.setItem(options.authCookieName, data.token);
      console.info("now is logged, token is: " + data.token);
      return data.token;
    } else {
      try {
        const data = await response.json();
        throw new Error(JSON.stringify(data));
      } catch (err) {
        throw err;
      }
    }
  }
  static async socialLoginOauthAnswer(
    detail: {
      token?: string;
      provider: string;
      tmpCode?: string;
      redirect_uri?: string;
    },
    options: { authUrl: string; authCookieName?: string }
  ) {
    console.log("auth socialLoginOauthAnswer", detail);
    try {
      if (!detail?.provider) {
        return console.error("auth socialLoginOauthAnswer: no provider");
      }
      const payload = {
        provider: detail.provider,
        token: (detail.token || detail.tmpCode) as string,
        redirect_uri: detail.redirect_uri,
      };
      if (!payload.token) {
        return console.error("auth socialLoginOauthAnswer: no token");
      }

      return await Authorize.authorizeSocialLogin(payload, options);
    } catch (err) {
      console.error("auth socialLoginOauthAnswer:", err);
    }
  }
}
