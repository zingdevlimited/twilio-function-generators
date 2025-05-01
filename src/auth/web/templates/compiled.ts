// @ts-nocheck
import {TemplateDelegate, template} from "handlebars";

export const callback:TemplateDelegate = template({"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var helper, alias1=depth0 != null ? depth0 : (container.nullContext || {}), alias2=container.hooks.helperMissing, alias3="function", alias4=container.escapeExpression, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<html>\n    <head>\n        <title>"
    + alias4(((helper = (helper = lookupProperty(helpers,"title") || (depth0 != null ? lookupProperty(depth0,"title") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"title","hash":{},"data":data,"loc":{"start":{"line":3,"column":15},"end":{"line":3,"column":24}}}) : helper)))
    + "</title>\n    </head>\n    <body>\n        <div id=\"main\">\n            <p id=\"message\">\n                "
    + alias4(((helper = (helper = lookupProperty(helpers,"message") || (depth0 != null ? lookupProperty(depth0,"message") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"message","hash":{},"data":data,"loc":{"start":{"line":8,"column":16},"end":{"line":8,"column":27}}}) : helper)))
    + "\n            </p>\n            <a id=\"navLink\" href=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"navLinkUrl") || (depth0 != null ? lookupProperty(depth0,"navLinkUrl") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"navLinkUrl","hash":{},"data":data,"loc":{"start":{"line":10,"column":34},"end":{"line":10,"column":48}}}) : helper)))
    + "\">"
    + alias4(((helper = (helper = lookupProperty(helpers,"navLinkLabel") || (depth0 != null ? lookupProperty(depth0,"navLinkLabel") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"navLinkLabel","hash":{},"data":data,"loc":{"start":{"line":10,"column":50},"end":{"line":10,"column":66}}}) : helper)))
    + "</a>\n        </div>\n        <input id=\"status\" type=\"hidden\" value=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"status") || (depth0 != null ? lookupProperty(depth0,"status") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"status","hash":{},"data":data,"loc":{"start":{"line":12,"column":48},"end":{"line":12,"column":58}}}) : helper)))
    + "\"/>\n        <script type=\"text/javascript\">\n            const status = document.getElementById(\"status\").value;\n            if(status !== \"SUCCESS\"){\n                return;\n            }\n            \n            try{\n                const redirectTo = window.sessionStorage.getItem(\""
    + alias4(((helper = (helper = lookupProperty(helpers,"id") || (depth0 != null ? lookupProperty(depth0,"id") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"id","hash":{},"data":data,"loc":{"start":{"line":20,"column":66},"end":{"line":20,"column":72}}}) : helper)))
    + "_redirectToUrl\");\n                if(typeof(redirectTo) === \"string\"){\n                    const redirectToUrl = new URL(redirectTo);\n                    window.location.replace(redirectToUrl);\n                    return;\n                }\n            }\n            catch(err){\n                console.error(\"failed to parse redirectToUrl\", err);\n            }\n            const navLink = document.getElementById(\"navLink\");\n            window.location.replace(navLink.href);\n        </script>\n    </body>\n</html>";
},"useData":true});