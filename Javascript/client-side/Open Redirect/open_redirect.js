// Example 1: Basic redirect with user input
function redirectUser(url) {
    window.location = url;  // Vulnerable: no validation
}

// Example 2: Express.js redirect with query parameter
app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url;
    res.redirect(redirectUrl);  // Vulnerable: no validation
});

// Example 3: React component with redirect from URL parameter
function RedirectComponent() {
    const urlParams = new URLSearchParams(window.location.search);
    const destination = urlParams.get('to');
    
    useEffect(() => {
        if (destination) {
            window.location.href = destination;  // Vulnerable: no validation
        }
    }, [destination]);
}

// Example 4: Angular service with vulnerable navigation
@Injectable()
export class RedirectService {
    constructor(private router: Router) {}
    
    navigateToPage(returnUrl) {
        this.router.navigateByUrl(returnUrl);  // Vulnerable: no validation
    }
}

// Example 5: URL construction with template literals
function redirectToProfile(username) {
    const url = `${getRedirectBase()}?user=${username}&redirect=${getParameterByName('redirect')}`;
    location.replace(url);  // Vulnerable: using unvalidated redirect parameter
}