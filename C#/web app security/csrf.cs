// VULNERABLE CODE EXAMPLES FOR CSRF TESTING

// 1. Controller with POST action without ValidateAntiForgeryToken
public class UserController : Controller
{
    [HttpPost] // VULNERABLE: Missing [ValidateAntiForgeryToken]
    public ActionResult Create(UserModel model)
    {
        if (ModelState.IsValid)
        {
            _userService.CreateUser(model);
            return RedirectToAction("Index");
        }
        return View(model);
    }

    [HttpPut] // VULNERABLE: Missing [ValidateAntiForgeryToken]
    public ActionResult Update(int id, UserModel model)
    {
        _userService.UpdateUser(id, model);
        return Ok();
    }

    [HttpDelete] // VULNERABLE: Missing [ValidateAntiForgeryToken]
    public ActionResult Delete(int id)
    {
        _userService.DeleteUser(id);
        return Json(new { success = true });
    }

    [HttpPatch] // VULNERABLE: Missing [ValidateAntiForgeryToken]
    public ActionResult PartialUpdate(int id, JsonPatchDocument<UserModel> patch)
    {
        _userService.PatchUser(id, patch);
        return Ok();
    }
}

// 2. API Controller without CSRF protection
[ApiController] // VULNERABLE: Missing CSRF protection
public class ProductsController : ControllerBase
{
    [HttpPost]
    public ActionResult<Product> CreateProduct(Product product)
    {
        _productService.CreateProduct(product);
        return Ok(product);
    }

    [HttpDelete("{id}")]
    public ActionResult DeleteProduct(int id)
    {
        _productService.DeleteProduct(id);
        return NoContent();
    }
}

// 3. Controller with explicitly disabled CSRF validation
public class PaymentController : Controller
{
    [HttpPost]
    [IgnoreAntiforgeryToken] // VULNERABLE: Explicitly disabled CSRF protection
    public ActionResult ProcessPayment(PaymentModel model)
    {
        _paymentService.ProcessPayment(model);
        return View("Success");
    }
}

// 4. Startup.cs without global CSRF protection
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc(); // VULNERABLE: Missing global CSRF configuration
        
        // VULNERABLE: Missing SameSite configuration
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
        });
    }
}

// 5. Alternative vulnerable startup configuration
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        
        builder.Services.AddControllersWithViews(); // VULNERABLE: No global CSRF filter
        
        var app = builder.Build();
        
        app.UseRouting();
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");
        
        app.Run();
    }
}

// 6. Account Controller with sensitive operations
public class AccountController : Controller
{
    [HttpPost] // VULNERABLE: Password change without CSRF protection
    public ActionResult ChangePassword(ChangePasswordModel model)
    {
        if (ModelState.IsValid)
        {
            _accountService.ChangePassword(User.Identity.Name, model.NewPassword);
            return RedirectToAction("Profile");
        }
        return View(model);
    }

    [HttpPost] // VULNERABLE: Account deletion without CSRF protection
    public ActionResult DeleteAccount()
    {
        _accountService.DeleteAccount(User.Identity.Name);
        return RedirectToAction("Logout");
    }

    [HttpPost] // VULNERABLE: Email change without CSRF protection
    public ActionResult ChangeEmail(string newEmail)
    {
        _accountService.ChangeEmail(User.Identity.Name, newEmail);
        return Json(new { success = true });
    }
}

// 7. Admin Controller with privileged operations
public class AdminController : Controller
{
    [HttpPost] // VULNERABLE: User role changes without CSRF protection
    public ActionResult AssignRole(int userId, string role)
    {
        _userService.AssignRole(userId, role);
        return RedirectToAction("Users");
    }

    [HttpDelete] // VULNERABLE: Bulk user deletion without CSRF protection
    public ActionResult BulkDeleteUsers(int[] userIds)
    {
        _userService.BulkDeleteUsers(userIds);
        return Json(new { success = true });
    }
}

// 8. Financial Controller
public class BankingController : Controller
{
    [HttpPost] // VULNERABLE: Money transfer without CSRF protection
    public ActionResult TransferMoney(TransferModel model)
    {
        _bankingService.TransferMoney(model.FromAccount, model.ToAccount, model.Amount);
        return View("TransferSuccess");
    }

    [HttpPost] // VULNERABLE: Account settings change without CSRF protection
    public ActionResult UpdateBankingSettings(BankingSettingsModel model)
    {
        _bankingService.UpdateSettings(User.Identity.Name, model);
        return RedirectToAction("Settings");
    }
}

// Models for reference
public class UserModel
{
    public string Name { get; set; }
    public string Email { get; set; }
    public string Role { get; set; }
}

public class PaymentModel
{
    public decimal Amount { get; set; }
    public string CardNumber { get; set; }
    public string CardHolderName { get; set; }
}

public class ChangePasswordModel
{
    public string CurrentPassword { get; set; }
    public string NewPassword { get; set; }
    public string ConfirmPassword { get; set; }
}

public class TransferModel
{
    public string FromAccount { get; set; }
    public string ToAccount { get; set; }
    public decimal Amount { get; set; }
}

public class BankingSettingsModel
{
    public bool AllowInternationalTransfers { get; set; }
    public decimal DailyLimit { get; set; }
    public string NotificationEmail { get; set; }
}
