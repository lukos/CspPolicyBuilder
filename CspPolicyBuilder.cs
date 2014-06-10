//
// FileName: CspPolicyBuilder.cs
// Author: Luke Briner
// Copyright (C) 2014 PixelPin Ltd
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PixelPin.Security
{
    /// <summary>
    /// Builds the text for the Content Security Policy HTTP header
    /// </summary>
    /// <remarks>The HTTP header is designed to restrict what domains your site can load resources from. It also prevents inline scripts and the
    /// javascript eval() function. This is designed to prevent various cross-site-scripting (XSS) attacks, which are often created by either a
    /// directly injected script or by injecting a script reference to an external script.
    /// 
    /// Use this class to aid the building of the header tag which can then be added to the response using Response.AddHeader()
    /// 
    /// The defaults are set to what seems reasonable for most sites. For example, most sites will load styles and scripts but not many will load
    /// objects and media, therefore the default are set to 'self' for the first two and 'none' for the second two. This can either be overridden
    /// by modifying the defaults or just to add the relevant value to the list of sources.</remarks>
    public class CspPolicyBuilder
    {
        /// <summary>
        /// Standard (recommended) header
        /// </summary>
        public const string CSP_HEADER_TITLE = "Content-Security-Policy";
        /// <summary>
        /// The previous experimental header that might be useful in addition to the standard one for IE compatibility until they catch up
        /// </summary>
        public const string CSP_HEADER_ALT_TITLE = "X-Content-Security-Policy";
        /// <summary>
        /// To be used in place of CSP_HEADER_TITLE when testing your deployment. This will cause the browser to report the errors but not enforce them
        /// </summary>
        public const string CSP_HEADER_TITLE_REPORT_ONLY = "Content-Security-Policy-Report-Only";

        public const string SELF_TAG = "'self'";
        public const string NONE_TAG = "'none'";

        private const string END_BLOCK = ";";   // How the separate sources are delimited

        public CspPolicyBuilder()
        {
            ConnectSources = new List<string>();
            FontSources = new List<string>();
            FrameSources = new List<string>();
            ImageSources = new List<string>();
            MediaSources = new List<string>();
            ObjectSources = new List<string>();
            StyleSources = new List<string>();
            ScriptSources = new List<string>();
        }

        /// <summary>
        /// Gets or sets the list of sources that the page can connect to using XHR, web sockets and event source. Defaults to none
        /// </summary>
        public List<string> ConnectSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can download web fonts from. Defaults to self
        /// </summary>
        public List<string> FontSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that can be hosted in frames on this page. Defaults to none
        /// </summary>
        public List<string> FrameSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can load images from. Defaults to self
        /// </summary>
        public List<string> ImageSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can load images from. Defaults to none
        /// </summary>
        public List<string> MediaSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can load objects from (such as Flash). Defaults to none
        /// </summary>
        public List<string> ObjectSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can load styles from. Defaults to self
        /// </summary>
        public List<string> StyleSources { get; set; }

        /// <summary>
        /// Gets or sets the list of sources that the page can load scripts from. Defaults to self
        /// </summary>
        public List<string> ScriptSources { get; set; }

        /// <summary>
        /// Gets or sets the url that will be called by the browser if a policy fails
        /// </summary>
        /// <remarks>This URL will be posted to with data in JSON format equivalent to the following:
        /// {
        ///     "csp-report": {
        ///     "document-uri": "http://example.org/page.html",
        ///     "referrer": "http://evil.example.com/",
        ///     "blocked-uri": "http://evil.example.com/evil.js",
        ///     "violated-directive": "script-src 'self' https://apis.google.com",
        ///     "original-policy": "script-src 'self' https://apis.google.com; report-uri http://example.org/my_amazing_csp_report_parser"
        ///   }
        /// }
        /// </remarks>
        public string ReportingUrl { get; set; }

        /// <summary>
        /// Whether to permit the use of eval() in the page, a generally unsafe practice that should be avoided due to its security weaknesses. Defaults to false.
        /// </summary>
        public bool AllowEval { get; set; }

        /// <summary>
        /// Whether to permit the use of inline script, which would remove some of the reason for using CSP in the first place. Defaults to false.
        /// </summary>
        public bool AllowInlineScript { get; set; }

        /// <summary>
        /// Whether to permit the use of inline style, which would remove some of the reason for using CSP in the first place. Defaults to false.
        /// </summary>
        public bool AllowInlineStyle { get; set; }

        /// <summary>
        /// Gets or sets the default scope for the CSP. All other tags will inherit this by default (unless they override it). Defaults to none.
        /// </summary>
        /// <remarks>
        /// This default will be set at the top level for the site so any sections that are not explicitly specified will inherit this
        /// value
        /// </remarks>
        public string DefaultScope { get; set; }
        private string DefaultScopeCalculated;      // Worked out from the presence or not of DefaultScope

        /// <summary>
        /// Returns the value for this header, correctly formatted
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            CalculateDefault();

            var sb = new StringBuilder();
            
            sb.Append("default-src ");
            sb.Append(DefaultScopeCalculated);
            sb.Append(END_BLOCK);

            // Fonts, images, styles and scripts all default to self, connect, frame, media and object all default to none
            sb.Append(CreateBlock("font-src", SELF_TAG, FontSources));
            sb.Append(CreateBlock("img-src", SELF_TAG, ImageSources));
            sb.Append(CreateBlock("style-src", SELF_TAG, StyleSources));
            sb.Append(CreateBlock("script-src", SELF_TAG, ScriptSources));
            sb.Append(CreateBlock("connect-src", NONE_TAG, ConnectSources));
            sb.Append(CreateBlock("frame-src", NONE_TAG, FrameSources));
            sb.Append(CreateBlock("media-src", NONE_TAG, MediaSources));
            sb.Append(CreateBlock("object-src", NONE_TAG, ObjectSources));

            return sb.ToString();
        }

        /// <summary>
        /// Adds the required single quotes to none, unsafe-inline, unsafe-eval and self if they are not already provided.
        /// </summary>
        /// <param name="input">The user-supplied input section name</param>
        /// <returns>The input quoted if it is not already quoted</returns>
        private string AddQuotesIfNotPresent(string input)
        {
            if (input == "none"
                || input == "self"
                || input == "unsafe-inline"
                || input == "unsafe-eval")
            {
                return "'" + input + "'";
            }
            return input;
        }

        /// <summary>
        /// Works out the default scope for all tags
        /// </summary>
        private void CalculateDefault()
        {
            DefaultScopeCalculated = String.IsNullOrWhiteSpace(DefaultScope) ? "'none' " : AddQuotesIfNotPresent(DefaultScope);
        }

        /// <summary>
        /// Creates the CSP block for the given section
        /// </summary>
        /// <param name="tag">The name of the section e.g. script-src</param>
        /// <param name="defaultValue">The default value for this section if no entries are present</param>
        /// <param name="entries">The URL entries for this section or an empty list</param>
        /// <returns>The string to add to the CSP header</returns>
        private string CreateBlock(string tag, string defaultValue, List<string> entries)
        {
            if (entries.Count == 0 && defaultValue == DefaultScopeCalculated)
                // If no entries and it matches the main default, no need to add anything in
                return String.Empty;

            var sb = new StringBuilder();
            sb.Append(tag);
            if (entries.Count == 0)
            {
                sb.Append(" " + defaultValue);
            }
            else
            {
                entries.ForEach(p => sb.Append(" " + p));
            }
            // Special handling for script and style additional tags
            if (tag == "script-src")
            {
                if ( AllowEval )
                    sb.Append(" 'unsafe-eval'");
                if (AllowInlineScript)
                    sb.Append(" 'unsafe-inline'");
            }

            if (tag == "style-src")
            {
                if (AllowInlineStyle)
                    sb.Append(" 'unsafe-inline'");
            }

            sb.Append(END_BLOCK);
            return sb.ToString();
        }
    }
}
