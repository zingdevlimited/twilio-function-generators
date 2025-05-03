// @ts-nocheck
import {TemplateDelegate, template} from "handlebars";

export const authServiceCallback:TemplateDelegate = template({"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var helper, alias1=depth0 != null ? depth0 : (container.nullContext || {}), alias2=container.hooks.helperMissing, alias3="function", alias4=container.escapeExpression, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<!DOCTYPE html>\n<html>\n    <head>\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n        <link rel=\"icon\" type=\"image/x-icon\" href=\"favicon.ico\" />\n        <title>Login Callback</title>\n    </head>\n    <body>\n        <div id=\"main\">\n            <p class=\"message\">\n                "
    + alias4(((helper = (helper = lookupProperty(helpers,"message") || (depth0 != null ? lookupProperty(depth0,"message") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"message","hash":{},"data":data,"loc":{"start":{"line":11,"column":16},"end":{"line":11,"column":27}}}) : helper)))
    + "\n            </p>\n            <noscript>\n                <p class=\"message noscript\">\n                    Javascript has been disabled, click the link below to go to the homepage.\n                </p>\n                <p class=\"link-container\">\n                    <a id=\"navLink\" href=\"/\">Go Home</a>\n                </p>\n            </noscript>\n        </div>\n        <input id=\"status\" type=\"hidden\" value=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"status") || (depth0 != null ? lookupProperty(depth0,"status") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"status","hash":{},"data":data,"loc":{"start":{"line":22,"column":48},"end":{"line":22,"column":58}}}) : helper)))
    + "\"/>\n        <script type=\"text/javascript\">\n            (() => {\n                const status = document.getElementById(\"status\").value;\n                if(status !== \"SUCCESS\"){\n                    return;\n                }\n                \n                try{\n                    const redirectTo = window.sessionStorage.getItem(\"z_tfg_oidc_cbr\");\n                    if(typeof(redirectTo) === \"string\"){\n                        const redirectToUrl = new URL(redirectTo);\n                        window.location.replace(redirectToUrl);\n                        return;\n                    }\n                }\n                catch(err){\n                    console.error(\"failed to parse z_tfg_oidc_cbr session key to URL\", err);\n                }\n                console.log(\"redirecting to homepage (/)\")\n                window.location.replace(\"/\");\n            })();\n        </script>\n    </body>\n</html>";
},"useData":true});
export const loginRedirectError:TemplateDelegate = template({"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<!DOCTYPE html>\n<html>\n    <head>\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n        <link rel=\"icon\" type=\"image/x-icon\" href=\"favicon.ico\" />\n        <title>Login Redirect - Error</title>\n    </head>\n    <body>\n        <div id=\"main\">\n            <p class=\"message\">\n                "
    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"message") || (depth0 != null ? lookupProperty(depth0,"message") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"message","hash":{},"data":data,"loc":{"start":{"line":11,"column":16},"end":{"line":11,"column":27}}}) : helper)))
    + "\n            </p>\n            <p class=\"link-container\">\n                <a id=\"navLink\" href=\"/\">Go Home</a>\n            </p>\n        </div>\n    </body>\n</html>";
},"useData":true});
export const loginRedirectSuccess:TemplateDelegate = template({"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<!DOCTYPE html>\n<html>\n    <head>\n        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n        <link rel=\"icon\" type=\"image/x-icon\" href=\"favicon.ico\" />\n        <title>Login Redirect</title>\n    </head>\n    <body>\n        <div id=\"main\">\n            <p class=\"message\">\n                Redirecting you to your login provider, please wait ...\n            </p>\n            <noscript>\n                <p class=\"message noscript\">\n                    Javascript has been disabled, please click the link below to continue.\n                </p>\n                <p class=\"link-container\">\n                    <a id=\"navLink\" href=\""
    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"navLinkUrl") || (depth0 != null ? lookupProperty(depth0,"navLinkUrl") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"navLinkUrl","hash":{},"data":data,"loc":{"start":{"line":18,"column":42},"end":{"line":18,"column":56}}}) : helper)))
    + "\">Redirect to Login Provider</a>\n                </p>\n            </noscript>\n            \n        </div>\n        <script type=\"text/javascript\">\n            const navLink = document.getElementById(\"navLink\");\n            window.location.replace(navLink.href);\n        </script>\n    </body>\n</html>";
},"useData":true});