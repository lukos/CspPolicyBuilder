CspPolicyBuilder
================

A .Net class to aid setting up a site Content Security Policy to meet the requirements of the [w3c spec](http://www.w3.org/TR/CSP/)

What is Content Security Policy?
--------------------------------

From [wikipedia](http://en.wikipedia.org/wiki/Content_Security_Policy)

"Content Security Policy (CSP) is a computer security concept, to prevent cross-site scripting (XSS) and related attacks."

What it basically does it uses an HTTP header in the response to a web request which tells the browser from which URLs it is allowed to load resources from. This can be set globally or specified in sections for images, fonts, media, frames, ajax connects, objects, styles and scripts. For instance, you can tell the browser not to load fonts from anywhere (using "none"), allow image loading only from the same URL as the site (using "self") and perhaps load jQuery from a CDN, which you could do by setting "script-src: https://oss.maxcdn.com". By doing this, you limit the damage that an attacker could do, if they were able to inject some kind of resource tag into your web page using an XSS or injection type attack.

In addition to this, it is possible to tell the browser not to allow inline scripts (ones that are defined directly in the HTML rather than in external files) and likewise to prohibit inline CSS. This is because it is possible to inject scripts and bad css directly into a page - something that would not be helped by prohibiting the URLs of external resources. In a similar way, you can prohibit the use of JavaScript eval(), a very insecure mechanism, which can easily attacks by executing arbitrary text from a page.

Used together, these two methods are a reasonably easy way to add security to your application. The current working draft is [here](http://www.w3.org/TR/CSP/)

How to use it
-------------

1. Download the class and add it to your project
2. Use it like the following example:

```C#
var cspb = new CspPolicyBuilder();
cspb.ImageSources.Add(CspPolicyBuilder.SELF_TAG);
cspb.ImageSources.Add("https://www.google-analytics.com");
cspb.ImageSources.Add("https://stats.g.doubleclick.net");
cspb.ScriptSources.Add(CspPolicyBuilder.SELF_TAG);
cspb.ScriptSources.Add("https://www.google-analytics.com");
cspb.ScriptSources.Add("https://stats.g.doubleclick.net");
cspb.ScriptSources.Add("https://ajax.googleapis.com");
cspb.ScriptSources.Add("https://oss.maxcdn.com");
cspb.AllowInlineScript = true;
cspb.AllowInlineStyle = true;
cspb.AllowEval = true;
Response.AddHeader(CspPolicyBuilder.CSP_HEADER_TITLE_REPORT_ONLY, cspb.ToString());
```

Note that this example uses the "report only" setting which tells the browser to log console errors if it finds something that is prohibited but NOT to stop the resource being loaded or the method being called. This is very useful for testing your site before changing the header to CSP_HEADER_TITLE which is the standard. It is also worth adding the same text to the CSP_HEADER_ALT_TITLE header which is the experimental one that older browsers will still use.

Reporting Back to Base
----------------------
A very useful feature of CSP is to get the browsers to report back to a specified URL with any CSP failures. This might highlight whether you site is being attacked. To do this, set the value of ReportingUrl to a URL that will be POST'd to with some JSON in the format as found in the code comments.

Contributing
------------
Please feel free to add Pull Requests for any bugs you have fixed or if you feel like adding a project and unit tests etc. You can contact me via my blog at lukieb.blogspot.co.uk
