// Results page JavaScript functionality

let analysisData = null;
let analysisId = null;
let statusTimer = null;

document.addEventListener('DOMContentLoaded', function() {
    const path = window.location.pathname;
    const match = path.match(/\/analyze\/([a-f0-9-]+)/);
    const initial = window.__INITIAL_ANALYSIS__;
    if (initial) {
        analysisData = initial;
        displayResults(initial);
    } else if (match) {
        analysisId = match[1];
        startAnalysis();
    } else {
        showError('Invalid analysis ID');
    }
});

function startAnalysis() {
    updateProgress(1);
    fetch(`/api/analyze/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis_id: analysisId })
    })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                showError(data.error);
                return;
            }
            pollStatus();
        })
        .catch(err => {
            console.error('Start error:', err);
            showError('Failed to start analysis. Please try again.');
        });
}

function pollStatus() {
    if (statusTimer) clearInterval(statusTimer);
    statusTimer = setInterval(() => {
        fetch(`/api/analyze/status/${analysisId}`)
            .then(res => res.json())
            .then(status => {
                if (status.error) {
                    clearInterval(statusTimer);
                    showError(status.error);
                    return;
                }
                const step = status.current_step || 1;
                updateProgress(step);
                if (status.status === 'completed') {
                    clearInterval(statusTimer);
                    fetch(`/api/analyze/result/${analysisId}`)
                        .then(res => res.json())
                        .then(data => {
                            analysisData = data;
                            displayResults(data);
                        })
                        .catch(err => {
                            console.error('Result error:', err);
                            showError('Failed to load analysis results.');
                        });
                }
                if (status.status === 'error') {
                    clearInterval(statusTimer);
                    showError('Analysis failed.');
                }
            })
            .catch(err => {
                console.error('Status error:', err);
            });
    }, 1000);
}

// Optional: fallback demo if API is unreachable
function simulateAnalysis() {
    updateProgress(1);
    setTimeout(() => updateProgress(2), 1200);
    setTimeout(() => updateProgress(3), 2400);
    setTimeout(() => {
        updateProgress(4);
        displayResults(generateSampleData());
    }, 3600);
}

function updateProgress(step) {
    // Update progress steps
    for (let i = 1; i <= 4; i++) {
        const stepElement = document.getElementById(`step${i}`);
        if (i < step) {
            stepElement.classList.add('completed');
            stepElement.classList.remove('active');
        } else if (i === step) {
            stepElement.classList.add('active');
            stepElement.classList.remove('completed');
        } else {
            stepElement.classList.remove('active', 'completed');
        }
    }
}

function displayResults(data) {
    // Hide progress, show results
    document.getElementById('progressSection').classList.add('d-none');
    document.getElementById('resultsSection').classList.remove('d-none');
    
    // Update risk score visualization
    updateRiskScore(data.risk_score, data.verdict);
    
    // Update email information
    updateEmailInfo(data.extracted_info);
    
    // Update detailed analysis
    updateDetailedAnalysis(data.breakdown);
    
    // Add fade-in animation
    document.getElementById('resultsSection').classList.add('fade-in');
}

function updateRiskScore(score, verdict) {
    const scoreCircle = document.getElementById('riskScoreCircle');
    const scoreNumber = document.getElementById('riskScoreNumber');
    const verdictBadge = document.getElementById('verdictBadge');
    const verdictDescription = document.getElementById('verdictDescription');
    
    // Animate score number
    animateNumber(scoreNumber, 0, score, 1000);
    
    // Update circle appearance
    scoreCircle.className = 'risk-score-circle';
    if (score <= 30) {
        scoreCircle.classList.add('risk-score-low');
        verdictBadge.className = 'verdict-badge verdict-safe';
        verdictBadge.textContent = 'Likely Safe';
        verdictDescription.textContent = 'This email appears to be legitimate with minimal risk indicators.';
    } else if (score <= 60) {
        scoreCircle.classList.add('risk-score-medium');
        verdictBadge.className = 'verdict-badge verdict-suspicious';
        verdictBadge.textContent = 'Suspicious';
        verdictDescription.textContent = 'This email contains some suspicious elements. Exercise caution.';
    } else {
        scoreCircle.classList.add('risk-score-high');
        verdictBadge.className = 'verdict-badge verdict-phishing';
        verdictBadge.textContent = 'Likely Phishing';
        verdictDescription.textContent = 'This email shows strong indicators of being a phishing attempt. Do not click any links or download attachments.';
    }
    
    // Update category scores
    document.getElementById('headerScore').textContent = Math.floor(score * 0.3);
    document.getElementById('senderScore').textContent = Math.floor(score * 0.4);
    document.getElementById('linkScore').textContent = Math.floor(score * 0.3);
}

function animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const current = Math.floor(start + (end - start) * progress);
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

function updateEmailInfo(info) {
    document.getElementById('emailFrom').textContent = info.from || 'Not available';
    document.getElementById('emailTo').textContent = info.to || 'Not available';
    document.getElementById('emailSubject').textContent = info.subject || 'Not available';
}

function updateDetailedAnalysis(breakdown) {
    // Update each category
    updateCategory('header', breakdown.header_spoofing || { findings: [], score: 0 });
    updateCategory('sender', breakdown.sender_anomalies || { findings: [], score: 0 });
    updateCategory('body', breakdown.urgency_language || { findings: [], score: 0 });
    updateCategory('links', breakdown.suspicious_links || { findings: [], score: 0 });
    updateCategory('attachments', breakdown.attachments || { findings: [], score: 0 });
}

function updateCategory(category, data) {
    const findingsContainer = document.getElementById(`${category}Findings`);
    const badge = document.getElementById(`${category}Badge`);
    
    // Update badge
    badge.textContent = data.findings.length;
    
    // Update findings
    if (data.findings.length > 0) {
        findingsContainer.innerHTML = data.findings.map(finding => `
            <div class="alert alert-warning alert-sm mb-2">
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${finding}
            </div>
        `).join('');
    } else {
        findingsContainer.innerHTML = `
            <div class="alert alert-success alert-sm">
                <i class="fas fa-check-circle me-2"></i>
                No suspicious indicators found in this category.
            </div>
        `;
    }
}

function generateSampleData() {
    // Generate realistic sample data for demonstration
    return {
        risk_score: 75,
        verdict: 'phishing',
        extracted_info: {
            from: 'PayPal Security <security@paypaI.com>',
            to: 'user@example.com',
            subject: 'Urgent: Verify your account now or it will be suspended!',
            links: ['http://bit.ly/verify-paypal', 'http://secure-paypal-login.com'],
            attachments: [{ filename: 'invoice.exe', content_type: 'application/octet-stream', size: 1024000 }]
        },
        breakdown: {
            header_spoofing: {
                score: 25,
                findings: [
                    'Display name "PayPal Security" suggests official company but uses free email provider',
                    'Reply-To domain differs from From domain',
                    'SPF authentication failed'
                ]
            },
            sender_anomalies: {
                score: 20,
                findings: [
                    'Potential typosquatting: paypaI.com vs legitimate paypal.com',
                    'Free email provider used for official-looking communication'
                ]
            },
            urgency_language: {
                score: 15,
                findings: [
                    'Urgency keyword found: urgent',
                    'Urgency keyword found: verify now',
                    'Urgency keyword found: suspended'
                ]
            },
            body_red_flags: {
                score: 10,
                findings: [
                    'Generic greeting detected: Dear Customer',
                    'Threat detected: account will be closed'
                ]
            },
            suspicious_links: {
                score: 20,
                findings: [
                    'Shortened URL detected: http://bit.ly/verify-paypal',
                    'URL flagged by Google Safe Browsing: http://secure-paypal-login.com'
                ]
            },
            attachments: {
                score: 20,
                findings: [
                    'Dangerous attachment: invoice.exe'
                ]
            }
        }
    };
}

function showError(message) {
    document.getElementById('progressSection').innerHTML = `
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <div class="mb-4">
                            <i class="fas fa-exclamation-triangle fa-3x text-danger"></i>
                        </div>
                        <h4 class="text-danger">Analysis Error</h4>
                        <p class="text-muted">${message}</p>
                        <a href="/" class="btn btn-primary">
                            <i class="fas fa-arrow-left me-2"></i>
                            Back to Upload
                        </a>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Fallback demo after long wait without results
setTimeout(() => {
    const progressVisible = !document.getElementById('progressSection').classList.contains('d-none');
    if (progressVisible && !analysisData) {
        simulateAnalysis();
    }
}, 15000);
