using System;
using System.Web;
using System.Web.Mvc;

public class VulnerableController : Controller
{
    // Rule 1: Direct output without encoding
    public void TestDirectOutput()
    {
        Response.Write(Request.QueryString["userInput"]); // VULNERABLE
        Response.Write("Hello " + Request.Form["name"]); // VULNERABLE
    }

    // Rule 2: ViewBag assignment
    public ActionResult TestViewBag()
    {
        ViewBag.UserMessage = Request.QueryString["msg"]; // VULNERABLE
        ViewBag.SearchTerm = HttpContext.Request.Query["q"]; // VULNERABLE
        return View();
    }

    // Rule 3: ViewData assignment
    public ActionResult TestViewData()
    {
        ViewData["error"] = Request.Form["error"]; // VULNERABLE
        ViewData["searchQuery"] = Request.QueryString["search"]; // VULNERABLE
        return View();
    }

    // Rule 4: Html.Raw usage
    public ActionResult TestHtmlRaw()
    {
        ViewBag.RawContent = Request.QueryString["content"];
        // In Razor view: @Html.Raw(ViewBag.RawContent) // VULNERABLE
        // In Razor view: @Html.Raw(Request.Query["html"]) // VULNERABLE
        return View();
    }

    // Rule 5: String concatenation
    public void TestStringConcatenation()
    {
        Response.Write("<div>" + Request.QueryString["msg"] + "</div>"); // VULNERABLE
        Response.Write("<span class='error'>" + Request.Form["error"] + "</span>"); // VULNERABLE
    }

    // Rule 6: JavaScript variable embedding
    public void TestJavaScriptVariable()
    {
        Response.Write("<script>var userData = '" + Request.QueryString["data"] + "';</script>"); // VULNERABLE
        Response.Write("<script>var config = {name: '" + ViewBag.UserName + "'};</script>"); // VULNERABLE
    }

    // Rule 7: URL parameters in attributes
    public void TestUrlInAttributes()
    {
        Response.Write("<a href='" + Request.QueryString["redirect"] + "'>Click</a>"); // VULNERABLE
        Response.Write("<img src='" + Request.Form["imageUrl"] + "' />"); // VULNERABLE
    }

    // Rule 8: Error message display
    public ActionResult TestErrorMessage()
    {
        try
        {
            // Some operation
        }
        catch
        {
            throw new Exception("Error processing: " + Request.QueryString["input"]); // VULNERABLE
        }
        
        ModelState.AddModelError("", "Invalid value: " + Request.Form["value"]); // VULNERABLE
        return View();
    }

    // Rule 9: Session display
    public void TestSessionDisplay()
    {
        Session["userName"] = Request.QueryString["user"]; // Store user input
        Response.Write("Welcome " + Session["userName"]); // VULNERABLE - displaying without encoding
    }

    // Rule 10: TempData display
    public ActionResult TestTempData()
    {
        TempData["message"] = Request.QueryString["msg"]; // Store user input
        ViewBag.TempMessage = TempData["message"]; // VULNERABLE - no encoding
        return View();
    }

    // Additional Rule 11: Unencoded HTML content injection
    public void TestHTMLContentInjection()
    {
        // Client-side JavaScript in ASP.NET page
        Response.Write("<script>document.getElementById('content').innerHTML = '" + Request.QueryString["html"] + "';</script>"); // VULNERABLE
        Response.Write("<script>document.write('" + Request.Form["content"] + "');</script>"); // VULNERABLE
    }

    // Additional Rule 12: JavaScript string direct injection
    public void TestJavaScriptStringInjection()
    {
        Response.Write("<script>var message = '" + Request.QueryString["msg"] + "';</script>"); // VULNERABLE
        ViewBag.JSData = Request.Form["data"];
        // In view: <script>processData('@ViewBag.JSData');</script> // VULNERABLE
    }

    // Additional Rule 13: JavaScript event handler injection
    public void TestEventHandlerInjection()
    {
        Response.Write("<button onclick='handleClick(\"" + Request.QueryString["param"] + "\")'>Click</button>"); // VULNERABLE
        Response.Write("<img onerror='alert(\"" + Request.Form["error"] + "\")' src='invalid.jpg' />"); // VULNERABLE
    }

    // Additional Rule 14: URL parameter direct reflection
    public void TestURLParameterReflection()
    {
        Response.Write(Request.QueryString["search"]); // VULNERABLE - direct reflection
        Response.Write("You searched for: " + Request.Params["query"]); // VULNERABLE
    }

    // Additional Rule 15: URL redirect parameter reflection
    public ActionResult TestURLRedirectReflection()
    {
        // Vulnerable redirect
        Response.Redirect(Request.QueryString["returnUrl"]); // VULNERABLE
        
        // Vulnerable href
        Response.Write("<a href='" + Request.QueryString["link"] + "'>Continue</a>"); // VULNERABLE
        return View();
    }

    // Additional Rule 16: Error message user input display
    public ActionResult TestErrorMessageDisplay()
    {
        ModelState.AddModelError("", "Invalid value provided: " + Request.Form["input"]); // VULNERABLE
        
        TempData["Error"] = "Error processing: " + Request.QueryString["data"]; // VULNERABLE
        
        try 
        {
            // Some operation
        }
        catch
        {
            throw new ArgumentException("Invalid parameter: " + Request.QueryString["param"]); // VULNERABLE
        }
        return View();
    }

    // Additional Rule 17: Error page parameter reflection
    protected void Application_Error(object sender, EventArgs e)
    {
        Exception ex = Server.GetLastError();
        Response.Write("Error occurred with input: " + Request.QueryString["input"]); // VULNERABLE
        Response.Write("Failed processing: " + HttpContext.Request.Form["data"]); // VULNERABLE
    }

    // Additional Rule 18: HTML meta tag injection
    public void TestMetaTagInjection()
    {
        Response.Write("<meta name='description' content='Search results for " + Request.QueryString["q"] + "' />"); // VULNERABLE
        Response.Write("<meta property='og:title' content='" + Request.Form["title"] + "' />"); // VULNERABLE
    }
}

// SECURE EXAMPLES FOR COMPARISON
public class SecureController : Controller
{
    public void SecureOutput()
    {
        Response.Write(HttpUtility.HtmlEncode(Request.QueryString["userInput"])); // SECURE
    }

    public ActionResult SecureViewBag()
    {
        ViewBag.UserMessage = HttpUtility.HtmlEncode(Request.QueryString["msg"]); // SECURE
        return View();
    }

    public void SecureJavaScript()
    {
        var jsData = HttpUtility.JavaScriptStringEncode(Request.QueryString["data"]);
        Response.Write($"<script>var userData = '{jsData}';</script>"); // SECURE
    }
}
