using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Html;
using System;

namespace VulnerableApp.Controllers
{
    public class VulnerableController : Controller
    {
        // VULNERABLE: Direct HTML injection without encoding
        public IActionResult Index()
        {
            ViewBag.UserName = Request.Query["name"];
            return View();
        }

        // VULNERABLE: Using Html.Raw with user input
        public IActionResult Profile()
        {
            ViewBag.Bio = Request.Query["bio"];
            return View();
        }

        // VULNERABLE: Direct assignment to innerHTML
        public IActionResult Dashboard()
        {
            ViewBag.Message = Request.Query["msg"];
            return View();
        }

        // VULNERABLE: Using user input in JavaScript eval
        public IActionResult Calculator()
        {
            ViewBag.Expression = Request.Query["expr"];
            return View();
        }

        // VULNERABLE: URL redirection without validation
        public IActionResult Redirect()
        {
            ViewBag.RedirectUrl = Request.Query["url"];
            return View();
        }

        // VULNERABLE: AJAX response handling
        [HttpPost]
        public IActionResult GetUserData(string userId)
        {
            var userData = $"<div>User: {Request.Form["input"]}</div>";
            return Json(new { html = userData });
        }

        // VULNERABLE: Script source manipulation
        public IActionResult LoadScript()
        {
            ViewBag.ScriptUrl = Request.Query["script"];
            return View();
        }

        // VULNERABLE: Document.write usage
        public IActionResult News()
        {
            ViewBag.NewsContent = Request.Query["content"];
            return View();
        }

        // VULNERABLE: jQuery html() method
        public IActionResult Comments()
        {
            ViewBag.Comment = Request.Query["comment"];
            return View();
        }

        // VULNERABLE: Response.Write without encoding
        public void DirectOutput()
        {
            Response.Write(Request.Query["data"]);
        }
    }
}

// VULNERABLE RAZOR VIEW EXAMPLES:

// Views/Vulnerable/Index.cshtml

@{
    ViewData["Title"] = "Vulnerable Page";
}

<!-- VULNERABLE: Direct output without encoding -->
<h1>Welcome @ViewBag.UserName</h1>

<!-- VULNERABLE: Using Html.Raw with user input -->
<div>@Html.Raw(ViewBag.Bio)</div>

<!-- VULNERABLE: JavaScript innerHTML assignment -->
<script>
    document.getElementById('message').innerHTML = '@ViewBag.Message';
</script>

<!-- VULNERABLE: Document.write with user input -->
<script>
    document.write('@ViewBag.NewsContent');
</script>

<!-- VULNERABLE: eval() usage -->
<script>
    var result = eval('@ViewBag.Expression');
    document.getElementById('result').innerHTML = result;
</script>

<!-- VULNERABLE: Location.href assignment -->
<script>
    window.location.href = '@ViewBag.RedirectUrl';
</script>

<!-- VULNERABLE: Script src assignment -->
<script>
    var script = document.createElement('script');
    script.src = '@ViewBag.ScriptUrl';
    document.head.appendChild(script);
</script>

<!-- VULNERABLE: jQuery html() method -->
<script>
    $('#comment-section').html('@ViewBag.Comment');
</script>

<!-- VULNERABLE: AJAX response handling -->
<script>
    $.post('/Vulnerable/GetUserData', { input: userInput }, function(data) {
        document.getElementById('user-data').innerHTML = data.html;
    });
</script>

<!-- VULNERABLE: URL parameter usage -->
<script>
    var urlParams = new URLSearchParams(window.location.search);
    var userParam = urlParams.get('user');
    document.getElementById('header').innerHTML = 'Hello ' + userParam;
</script>


// ADDITIONAL VULNERABLE PATTERNS:

public class MoreVulnerableExamples : Controller
{
    // VULNERABLE: ViewData usage
    public IActionResult ViewDataExample()
    {
        ViewData["UserInput"] = Request.Query["input"];
        return View();
    }

    // VULNERABLE: TempData usage
    public IActionResult TempDataExample()
    {
        TempData["Message"] = Request.Query["msg"];
        return RedirectToAction("Display");
    }

    public IActionResult Display()
    {
        return View();
    }

    // VULNERABLE: Model binding with direct output
    public IActionResult ModelExample(UserModel model)
    {
        return View(model);
    }

    // VULNERABLE: HttpContext usage
    public IActionResult HttpContextExample()
    {
        ViewBag.Data = HttpContext.Request.Query["data"];
        return View();
    }
}

public class UserModel
{
    public string Name { get; set; }
    public string Email { get; set; }
    public string Comment { get; set; }
    public string Bio { get; set; }
}

// VULNERABLE VIEW MODEL USAGE:

<!-- In Razor View -->
@model UserModel

<!-- VULNERABLE: Direct model output -->
<div>@Html.Raw(Model.Comment)</div>

<!-- VULNERABLE: Model property in JavaScript -->
<script>
    var userName = '@Model.Name';
    document.getElementById('welcome').innerHTML = 'Welcome ' + userName;
</script>

<!-- VULNERABLE: TempData in JavaScript -->
<script>
    document.getElementById('message').innerHTML = '@TempData["Message"]';
</script>

<!-- VULNERABLE: ViewData in jQuery -->
<script>
    $('#content').html('@ViewData["UserInput"]');
</script>


// Test payloads to verify detection:

1. ?name=<script>alert('XSS')</script>
2. ?bio=<img src=x onerror=alert('XSS')>
3. ?msg=<svg onload=alert('XSS')>
4. ?expr=alert('XSS')
5. ?url=javascript:alert('XSS')
6. ?script=data:text/javascript,alert('XSS')
7. ?content=<iframe src=javascript:alert('XSS')>
8. ?comment=<details open ontoggle=alert('XSS')>
9. ?data=<marquee onstart=alert('XSS')>
10. ?input=<style>@import'javascript:alert("XSS")'</style>
