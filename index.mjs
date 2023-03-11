"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Authorize {
    constructor(options) {
        this.authUrl = options.authUrl;
        this.authCookieName = options.authCookieName || "authToken";
    }
    async authorizeByToken(token) {
        return Authorize.authByToken(this.authUrl + "/token", token);
    }
    async checkLogin(token) {
        return Authorize.checkLogin(this.authUrl + "/token", this.authCookieName, token);
    }
    async authorizeSocialLogin(detail) {
        return Authorize.authorizeSocialLogin(detail, {
            authUrl: this.authUrl,
            authCookieName: this.authCookieName,
        });
    }
    async socialLoginOauthAnswer(detail) {
        return Authorize.socialLoginOauthAnswer(detail, {
            authUrl: this.authUrl,
            authCookieName: this.authCookieName,
        });
    }
    static async authByToken(tokenUri, token) {
        const auth = await fetch(tokenUri, {
            headers: { Authorization: token, "Content-Type": "application/json" },
            method: "POST",
            body: JSON.stringify({ token: token }),
        });
        if (auth.ok) {
            const decodedAuth = await auth.json();
            if (decodedAuth.error) {
                throw new Error("unauthorized");
            }
            else if (!decodedAuth.token) {
                console.error("no token on answer");
                throw new Error("no token on answer");
            }
            else {
                return decodedAuth.token;
            }
        }
        else {
            throw new Error("unauthorized");
        }
    }
    static async checkLogin(tokenUri, authCookieName, token) {
        if (!authCookieName)
            throw new Error("authCookieName is not defined");
        if (!tokenUri)
            throw new Error("tokenUri is not defined");
        let storageType = "localStorage";
        let tk;
        tk = localStorage.getItem(authCookieName);
        if (!tk) {
            tk = sessionStorage.getItem(authCookieName);
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
            }
            catch (err) {
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
            }
            catch (err) {
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
        }
        else {
            throw new Error("not authorized");
        }
    }
    static async authorizeSocialLogin(detail, options) {
        const url = options.authUrl + "/social/login";
        const response = await fetch(url, {
            headers: { "Content-Type": "application/json" },
            method: "POST",
            body: JSON.stringify(Object.assign({ redirect_uri: detail.redirect_uri }, detail)),
        });
        console.log("server answer with", response);
        if (response.ok) {
            const data = await response.json();
            if (options.authCookieName)
                localStorage.setItem(options.authCookieName, data.token);
            console.info("now is logged, token is: " + data.token);
            return data.token;
        }
        else {
            try {
                const data = await response.json();
                throw new Error(JSON.stringify(data));
            }
            catch (err) {
                throw err;
            }
        }
    }
    static async socialLoginOauthAnswer(detail, options) {
        console.log("auth socialLoginOauthAnswer", detail);
        try {
            if (!detail?.provider) {
                return console.error("auth socialLoginOauthAnswer: no provider");
            }
            const payload = {
                provider: detail.provider,
                token: (detail.token || detail.tmpCode),
                redirect_uri: detail.redirect_uri,
            };
            if (!payload.token) {
                return console.error("auth socialLoginOauthAnswer: no token");
            }
            await Authorize.authorizeSocialLogin(payload, options);
        }
        catch (err) {
            console.error("auth socialLoginOauthAnswer:", err);
        }
    }
}
exports.default = Authorize;
//# sourceMappingURL=index.mjs.map