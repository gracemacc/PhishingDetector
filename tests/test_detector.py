#!/usr/bin/env python3
"""
Test script for the Phishing Email Detector
Tests core functionality including email parsing and scoring
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parse_email_content, PhishingScorer

def test_email_parsing():
    """Test email parsing functionality"""
    print("🧪 Testing email parsing...")
    
    # Sample phishing email content
    email_content = """From: PayPal Security <security@paypaI.com>
To: user@example.com
Subject: Urgent: Verify your account now or it will be suspended!
Date: Mon, 22 Dec 2024 10:00:00 +0000
Reply-To: support@fake-paypal.com
Authentication-Results: spf=none (sender IP is) smtp.mailfrom=paypaI.com;

Dear Customer,

Your PayPal account has been temporarily restricted due to suspicious activity. 
You must verify your identity immediately or your account will be permanently suspended.

Click here to verify: http://bit.ly/verify-paypal-account

This is your final notice. Act now to prevent account closure.

Best regards,
PayPal Security Team"""
    
    try:
        # Test email parsing
        email_data = parse_email_content(email_content)
        
        print("✅ Email parsing successful!")
        print(f"   From: {email_data['from']}")
        print(f"   Subject: {email_data['subject']}")
        print(f"   Links found: {len(email_data['links'])}")
        print(f"   Attachments: {len(email_data['attachments'])}")
        
        return email_data
        
    except Exception as e:
        print(f"❌ Email parsing failed: {e}")
        return None

def test_scoring_engine(email_data):
    """Test the scoring engine"""
    print("\n🧪 Testing scoring engine...")
    
    try:
        scorer = PhishingScorer()
        risk_score, findings = scorer.calculate_score(email_data)
        
        print(f"✅ Scoring completed!")
        print(f"   Risk Score: {risk_score}/100")
        print(f"   Total Findings: {len(findings)}")
        
        # Determine verdict
        if risk_score <= 30:
            verdict = "🟢 Safe"
        elif risk_score <= 60:
            verdict = "🟡 Suspicious"
        else:
            verdict = "🔴 Phishing"
            
        print(f"   Verdict: {verdict}")
        
        # Show top findings
        print("\n📋 Top Findings:")
        for i, finding in enumerate(findings[:5], 1):
            print(f"   {i}. {finding}")
        
        return risk_score, findings
        
    except Exception as e:
        print(f"❌ Scoring failed: {e}")
        return None, []

def test_safe_email():
    """Test with a legitimate-looking email"""
    print("\n🧪 Testing with safe email...")
    
    safe_email = """From: John Doe <john.doe@company.com>
To: colleague@company.com
Subject: Meeting tomorrow
Date: Mon, 22 Dec 2024 09:00:00 +0000
Authentication-Results: spf=pass smtp.mailfrom=company.com;

Hi there,

Just a reminder about our team meeting tomorrow at 2 PM in conference room A.
Please bring the quarterly reports.

Thanks,
John"""
    
    try:
        email_data = parse_email_content(safe_email)
        scorer = PhishingScorer()
        risk_score, findings = scorer.calculate_score(email_data)
        
        print(f"✅ Safe email analysis completed!")
        print(f"   Risk Score: {risk_score}/100")
        print(f"   Findings: {len(findings)}")
        
        if risk_score <= 30:
            print("   🟢 Correctly identified as safe")
        else:
            print(f"   ⚠️  Unexpected high score for safe email")
            
        return risk_score
        
    except Exception as e:
        print(f"❌ Safe email test failed: {e}")
        return None

def main():
    """Run all tests"""
    print("🚀 Starting Phishing Email Detector Tests\n")
    
    # Test email parsing
    email_data = test_email_parsing()
    if not email_data:
        print("❌ Cannot proceed without working email parser")
        return 1
    
    # Test scoring engine
    risk_score, findings = test_scoring_engine(email_data)
    if risk_score is None:
        print("❌ Cannot proceed without working scoring engine")
        return 1
    
    # Test safe email
    safe_score = test_safe_email()
    
    # Summary
    print("\n📊 Test Summary:")
    print("=" * 50)
    print(f"Phishing Email Score: {risk_score}/100 ({len(findings)} findings)")
    print(f"Safe Email Score: {safe_score}/100")
    
    if risk_score > 60 and safe_score <= 30:
        print("✅ All tests passed! The detector is working correctly.")
        return 0
    else:
        print("⚠️  Some tests may need attention.")
        return 1

if __name__ == "__main__":
    exit(main())