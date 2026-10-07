// ==========================================
// SECURECODE - STATIC SECURITY SCANNER
// ==========================================

const scanButton = document.getElementById("scanBtn");
const codeInput = document.getElementById("codeInput");
const scanResults = document.getElementById("scanResults");


scanButton.addEventListener("click", runSecurityScan);


function runSecurityScan() {

    const code = codeInput.value;

    if (!code.trim()) {

        scanResults.innerHTML = `
            <div class="scan-item">
                <strong>⚠ No code provided</strong>
                <span>Please enter JavaScript code before starting the scan.</span>
            </div>
        `;

        return;
    }


    let findings = [];


    // ------------------------------------------
    // XSS / UNSAFE INNERHTML
    // ------------------------------------------

    if (/\.innerHTML\s*=/.test(code)) {

        findings.push({
            title: "Potential XSS Vulnerability",
            description:
                "The code uses innerHTML. Avoid inserting untrusted data directly into the DOM. Prefer textContent or safe DOM APIs."
        });

    }


    // ------------------------------------------
    // HARDCODED SECRETS
    // ------------------------------------------

    if (
        /(apiKey|api_key|password|secret|token)\s*=\s*["'`]/i.test(code)
    ) {

        findings.push({
            title: "Possible Hardcoded Secret",
            description:
                "A credential-like variable contains a hardcoded value. Secrets should not be stored directly in client-side source code."
        });

    }


    // ------------------------------------------
    // EVAL
    // ------------------------------------------

    if (/\beval\s*\(/i.test(code)) {

        findings.push({
            title: "Dangerous eval() Usage",
            description:
                "eval() can execute dynamically supplied JavaScript and should generally be avoided."
        });

    }


    // ------------------------------------------
    // DOCUMENT.WRITE
    // ------------------------------------------

    if (/document\.write\s*\(/i.test(code)) {

        findings.push({
            title: "Unsafe document.write() Usage",
            description:
                "document.write() can create injection risks when used with untrusted data."
        });

    }


    // ------------------------------------------
    // MISSING VALIDATION
    // ------------------------------------------

    if (
        /(prompt\s*\(|\.value)/i.test(code) &&
        !/(typeof|trim\(|length|test\(|includes\(|validation|validate)/i.test(code)
    ) {

        findings.push({
            title: "Insufficient Input Validation",
            description:
                "User-controlled input appears to be processed without obvious validation or sanitization."
        });

    }


    // ------------------------------------------
    // DISPLAY RESULTS
    // ------------------------------------------

    if (findings.length === 0) {

        scanResults.innerHTML = `
            <div class="scan-safe">
                ✓ No common insecure patterns detected.
                Continue with manual review and dependency/security testing.
            </div>
        `;

        return;
    }


    scanResults.innerHTML = findings.map((finding, index) => {

        return `
            <div class="scan-item">
                <strong>⚠ SC-${String(index + 1).padStart(3, "0")} — ${finding.title}</strong>
                <span>${finding.description}</span>
            </div>
        `;

    }).join("");

}


// ==========================================
// ACTIVE NAVIGATION EFFECT
// ==========================================

const sections = document.querySelectorAll("section[id]");
const navLinks = document.querySelectorAll(".navbar nav a");

window.addEventListener("scroll", () => {

    let current = "";

    sections.forEach(section => {

        const sectionTop = section.offsetTop;

        if (window.scrollY >= sectionTop - 150) {
            current = section.getAttribute("id");
        }

    });


    navLinks.forEach(link => {

        link.style.color = "";

        if (link.getAttribute("href") === "#" + current) {
            link.style.color = "#8d85ff";
        }

    });

});


// ==========================================
// BUTTON ANIMATION
// ==========================================

scanButton.addEventListener("click", () => {

    scanButton.textContent = "Scanning...";

    setTimeout(() => {
        scanButton.textContent = "Run Security Scan";
    }, 500);

});
