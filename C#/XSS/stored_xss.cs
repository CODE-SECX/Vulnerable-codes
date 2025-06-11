// Example 1: Direct Database to HTML Output (Rule 1)
public class VulnerableController : Controller
{
    public ActionResult ShowComments()
    {
        using (var connection = new SqlConnection(connectionString))
        {
            var command = new SqlCommand("SELECT Comment FROM Comments", connection);
            connection.Open();
            var reader = command.ExecuteReader();
            
            while (reader.Read())
            {
                // VULNERABLE: Direct output without encoding
                Response.Write("<div>" + reader["Comment"] + "</div>");
            }
        }
        return View();
    }
}

// Example 2: Razor Html.Raw with Database Data (Rule 2)
// In a Razor view (.cshtml)
public class CommentModel
{
    public string UserComment { get; set; }
}

// In the view:
// VULNERABLE: Using Html.Raw with user data
// @Html.Raw(Model.UserComment)

// Example 3: StringBuilder HTML Construction (Rule 3)
public string BuildUserProfile(DataTable userData)
{
    StringBuilder html = new StringBuilder();
    
    foreach (DataRow row in userData.Rows)
    {
        // VULNERABLE: Building HTML with unencoded data
        html.AppendFormat("<div class='profile'><h3>{0}</h3><p>{1}</p></div>", 
                         row["Name"], row["Bio"]);
    }
    
    return html.ToString();
}

// Example 4: JavaScript Variable Assignment (Rule 4)
public ActionResult UserDashboard()
{
    var user = GetCurrentUser();
    ViewBag.UserScript = $@"
        <script>
            var userName = '{user.Name}';  // VULNERABLE: Direct assignment
            var userBio = '{user.Biography}';  // VULNERABLE: Direct assignment
            displayUserInfo(userName, userBio);
        </script>";
    
    return View();
}

// Example 5: InnerHtml Assignment (Rule 5)
public partial class UserProfile : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        using (var connection = new SqlConnection(connectionString))
        {
            var command = new SqlCommand("SELECT Bio FROM Users WHERE Id = @id", connection);
            command.Parameters.AddWithValue("@id", userId);
            connection.Open();
            var reader = command.ExecuteReader();
            
            if (reader.Read())
            {
                // VULNERABLE: Direct assignment to InnerHtml
                userBioDiv.InnerHtml = reader["Bio"].ToString();
            }
        }
    }
}

// Example 6: Literal Control Text (Rule 6)
public partial class Comments : System.Web.UI.Page
{
    protected void DisplayComments()
    {
        var comments = GetCommentsFromDatabase();
        
        foreach (var comment in comments)
        {
            var literal = new Literal();
            // VULNERABLE: Unencoded text assignment
            literal.Text = $"<p>{comment.Content}</p><small>By: {comment.Author}</small>";
            commentsPanel.Controls.Add(literal);
        }
    }
}

// Example 7: Missing ValidateRequest (Rule 7)
[ValidateInput(false)]  // VULNERABLE: Disabling validation
public ActionResult ProcessComment(string comment)
{
    // Store comment in database
    SaveComment(comment);
    
    // Display comment
    ViewBag.Comment = comment;
    return View();
}

// Web.config example for Rule 7:
/*
<system.web>
  <pages validateRequest="false" />  <!-- VULNERABLE: Disabled validation -->
</system.web>
*/

// Example 8: Server Controls with Database Binding (Rule 8)
// In .aspx file:
/*
<asp:Repeater ID="CommentsRepeater" runat="server">
    <ItemTemplate>
        <div>
            <!-- VULNERABLE: Direct binding without encoding -->
            <%# Eval("CommentText") %>
            <br />
            Author: <%# DataBinder.Eval(Container.DataItem, "AuthorName") %>
        </div>
    </ItemTemplate>
</asp:Repeater>
*/

// Additional vulnerable patterns:

// Example 9: Entity Framework with direct output
public ActionResult ShowPosts()
{
    using (var context = new BlogContext())
    {
        var posts = context.Posts.ToList();
        string html = "";
        
        foreach (var post in posts)
        {
            // VULNERABLE: Entity data directly in HTML
            html += $"<article><h2>{post.Title}</h2><p>{post.Content}</p></article>";
        }
        
        return Content(html, "text/html");
    }
}

// Example 10: AJAX response with database data
public JsonResult GetUserData(int userId)
{
    var user = repository.GetUser(userId);
    
    // VULNERABLE: Raw HTML in JSON response
    return Json(new { 
        html = $"<div class='user'><h3>{user.Name}</h3><p>{user.Description}</p></div>"
    });
}

// Example 11: Custom control with database data
public class UserDisplayControl : WebControl
{
    protected override void Render(HtmlTextWriter writer)
    {
        var user = GetCurrentUser();
        
        // VULNERABLE: Direct HTML output
        writer.Write($"<div class='user-info'>{user.ProfileHtml}</div>");
    }
}

// Example 12: ViewData usage in controller
public ActionResult Profile(int id)
{
    var user = userRepository.GetById(id);
    
    // VULNERABLE: Storing raw HTML in ViewData
    ViewData["UserSignature"] = $"<em>{user.Signature}</em>";
    
    return View();
}

// Corresponding view usage:
// @Html.Raw(ViewData["UserSignature"])  // VULNERABLE

// Example 13: String interpolation with HTML
public string GenerateEmailBody(User user, string message)
{
    // VULNERABLE: User data in HTML template
    return $@"
        <html>
        <body>
            <h1>Hello {user.Name}!</h1>
            <p>{message}</p>
            <p>Your bio: {user.Biography}</p>
        </body>
        </html>";
}
