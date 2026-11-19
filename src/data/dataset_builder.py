"""
MailGuard Dataset Builder.
Downloads public phishing/ham datasets or generates a comprehensive, balanced,
and realistic benchmark sample dataset with real-world attack vectors and normal emails.
"""

import os
import csv
import re
import random
from typing import List, Dict, Tuple
import pandas as pd


# Real-world phishing templates across primary attack categories:
# 1. Credential harvesting (Banking, Cloud services, Microsoft 365, Google)
# 2. Urgent security / account suspension alerts
# 3. CEO fraud / Business Email Compromise (BEC) wire transfers
# 4. Fake invoice / payment advice
# 5. Delivery failure notifications (FedEx, DHL, USPS)
# 6. IT Support / MFA expiration notices
# 7. Lottery / crypto / tax refund scams
PHISHING_TEMPLATES = [
    {
        "subject": "CRITICAL: Your PayPal Account Has Been Suspended [Action Required]",
        "sender": "security-alert@paypa1-support-verify.com",
        "body": "Dear Valued Customer,\n\nWe detected unauthorized login attempts to your PayPal account from an unrecognized IP address (185.220.101.5). To protect your financial assets, your account access has been restricted immediately.\n\nYou must verify your identity within 24 hours or your balance will be permanently locked.\n\nClick here immediately to restore access:\nhttp://paypal-verification-center.info/login/restore.php?token=92847291\n\nFailure to confirm your credentials will result in legal escalation and account forfeiture.\n\nSecurity Team,\nPayPal Holdings Inc.",
        "label": 1,
        "category": "credential_phishing"
    },
    {
        "subject": "Urgent: Update your Microsoft 365 Password Immediately",
        "sender": "admin@m1crosoft-office365-auth.net",
        "body": "Office 365 Security Notice:\n\nYour organizational password will expire today in 2 hours. Due to company password policy revisions, all active sessions will be terminated unless you update your credentials right now.\n\nLog in to retain access to Outlook, SharePoint, and Teams:\nhttps://login.m1crosoft-sso-portal.xyz/common/oauth2/v2.0/authorize\n\nPlease do not ignore this notification. Your email mailbox will be queued for deactivation.",
        "label": 1,
        "category": "credential_phishing"
    },
    {
        "subject": "Quick task: Wire Transfer - Urgent Confidential",
        "sender": "ceo.executive.direct@gmail.com",
        "body": "Hi,\n\nAre you at your desk right now? I am currently wrapped up in an unexpected board meeting and unable to take incoming calls.\n\nWe urgently need to execute an emergency supplier payment of $48,500 before 3:00 PM today to secure an acquisition contract. Please let me know if you can process this wire right now from the corporate treasury account and I will forward the beneficiary wire coordinates.\n\nTreat this matter with the highest confidentiality.\n\nRegards,\nSent from my iPhone",
        "label": 1,
        "category": "bec_ceo_fraud"
    },
    {
        "subject": "INVOICE OVERDUE: INV-89214 past due payment notification",
        "sender": "billing-dept@globalinvoices-quickpay.top",
        "body": "ATTENTION: ACCOUNTS PAYABLE\n\nOur records indicate invoice INV-89214 for $14,230.00 remains unpaid despite multiple reminders. Late penalties of 12% per day are now being applied to your ledger.\n\nReview the breakdown and remit payment immediately to avert collection agency referral:\nhttp://194.38.20.12/billing/download_invoice_89214.html\n\nRemit wire payment today to freeze legal charges.",
        "label": 1,
        "category": "invoice_fraud"
    },
    {
        "subject": "DHL Express: Shipment #DHL-88901235 on hold at sorting hub",
        "sender": "delivery-notifications@dhl-tracking-express.link",
        "body": "Dear customer,\n\nYour package with tracking number #DHL-88901235 could not be delivered due to missing customs clearance fees ($2.95 USD) and incomplete postal address information.\n\nTo schedule immediate re-delivery to your residential address, please pay the outstanding customs duty:\nhttp://dhl-express-redelivery-portal.com/track?id=88901235\n\nUnclaimed packages will be returned to sender or destroyed within 48 hours.",
        "label": 1,
        "category": "delivery_scam"
    },
    {
        "subject": "IT Helpdesk: DUO Multi-Factor Authentication Re-enrollment",
        "sender": "it-support@company-servicedesk-reset.click",
        "body": "All Employees:\n\nOur corporate cybersecurity infrastructure is undergoing scheduled MFA certificate upgrades. Your current Duo Push device token has expired.\n\nTo ensure uninterrupted VPN and email access, re-authenticate your mobile token immediately:\nhttps://duo-security-sso-login.org/enroll/user/auth\n\nFailure to complete MFA enrollment before 5:00 PM will result in network lockout.",
        "label": 1,
        "category": "credential_phishing"
    },
    {
        "subject": "Wells Fargo Alert: Suspicious transaction detected on your debit card",
        "sender": "fraud-protection@wellsfargo-security-check.com",
        "body": "Wells Fargo Fraud Prevention Alert:\n\nA debit transaction of $1,842.00 at Apple Store Online was attempted using your card ending in 4108. Was this you?\n\nIf you did NOT authorize this transaction, click below immediately to cancel the charge and secure your online banking profile:\nhttp://wellsfargo.secure-dispute-resolve.com/auth/login.jsp\n\nProtecting your funds is our top priority.",
        "label": 1,
        "category": "financial_phishing"
    },
    {
        "subject": "Netflix: Your membership payment declined - update billing",
        "sender": "billing@netfl1x-subscription-support.cc",
        "body": "We were unable to process your monthly subscription payment with your primary card on file. Your streaming privileges are temporarily placed on hold.\n\nPlease update your payment details immediately to resume watching:\nhttps://netflix-account-update-center.com/signin\n\nWe hope to see you back soon.\nThe Netflix Team",
        "label": 1,
        "category": "credential_phishing"
    },
    {
        "subject": "Urgent: Purchase 5 Apple Gift Cards for Staff Recognition",
        "sender": "head.of.operations009@mail.com",
        "body": "Hey, are you free right now? I need you to run a quick confidential task for me. I am currently attending an offsite partner conference.\n\nI want to surprise some key department leads today with Apple gift cards. Can you go to the nearest store and purchase 5 physical cards valued at $100 each? Scratch the silver strip on the back and send photos of the codes to my email directly. I will process your expense reimbursement first thing tomorrow morning.\n\nLet me know once you are on your way.",
        "label": 1,
        "category": "bec_gift_card"
    },
    {
        "subject": "IRS Notice: Immediate Tax Refund Status Available - Ref #82734",
        "sender": "refunds@irs-tax-settlement-gov.online",
        "body": "Internal Revenue Service (IRS) Notification:\n\nOur annual audit of your 2025 federal tax filings determined you are entitled to an unclaimed tax refund of $2,450.80.\n\nTo deposit the refund directly into your verified bank account, please submit your direct deposit details and Social Security verification:\nhttp://irs-gov-tax-refund-portal.us/direct-deposit\n\nRefund claims not submitted by the deadline will lapse to the federal treasury.",
        "label": 1,
        "category": "scam_lottery"
    },
    {
        "subject": "Your Google Workspace storage is full (99.8%)",
        "sender": "storage-alert@goog1e-cloud-drive.info",
        "body": "Google Workspace Alert:\n\nYour mailbox and Drive storage quota has reached 14.98 GB of 15.00 GB. Incoming emails will bounce within 6 hours unless extra quota is provisioned or old emails purged.\n\nClick here to claim free 20GB institutional upgrade:\nhttp://google-drive-quota-upgrade.biz/auth\n\nGoogle Cloud Team",
        "label": 1,
        "category": "credential_phishing"
    },
    {
        "subject": "Chase Online: Important Security Update for Your Online Profile",
        "sender": "no-reply@chase-bank-secure-access.com",
        "body": "Dear Customer,\n\nWe regularly audit customer accounts to comply with federal Know-Your-Customer (KYC) regulations. Your profile requires immediate verification of billing contact and debit credentials.\n\nVerify your account to avoid temporary ATM card freeze:\nhttps://chase-online-customer-verify.com/servicing\n\nThank you for banking with Chase.",
        "label": 1,
        "category": "financial_phishing"
    },
    {
        "subject": "FedEx: Delivery attempt failed for parcel 77391823901",
        "sender": "tracking@fedex-shipping-update.site",
        "body": "FedEx Delivery Manager:\n\nOur driver was unable to deliver your package at 11:24 AM due to no adult signature at the premises.\n\nPlease confirm your delivery slot and print the customs dispatch docket:\nhttp://185.192.11.89/fedex/docket_print.php\n\nStorage charges will accrue after 3 business days.",
        "label": 1,
        "category": "delivery_scam"
    },
    {
        "subject": "AMAZON ORDER CONFIRMATION: Order #702-8829104-39102",
        "sender": "auto-confirm@amazon-order-receipts.shop",
        "body": "Thank you for shopping with Amazon.com!\n\nYou have purchased:\n1x Sony Alpha a7 IV Mirrorless Camera - $2,498.00\nShipping Address: 4820 Grand Concourse, Bronx, NY 10451\n\nIf you did not authorize this order, your Amazon account may be compromised. Call our fraud hotline or click below immediately to cancel the charge before it ships:\nhttp://amazon-order-cancel-fraud-prevention.top/cancel?order=7028829104\n\nAmazon Support Services",
        "label": 1,
        "category": "financial_phishing"
    },
    {
        "subject": "Cryptocurrency Investment Dividend: 1.45 BTC credited to your wallet",
        "sender": "reward@binance-airdrop-payouts.xyz",
        "body": "Congratulations!\n\nYour active wallet address was randomly selected in the Web3 ecosystem reward pool. 1.45 BTC has been reserved under your wallet reference #BTC-99182.\n\nTo authorize payout transaction to your local exchange:\nhttp://crypto-airdrop-claim-portal.click/withdraw?token=89218\n\nGas fees are covered. Offer valid for 12 hours only.",
        "label": 1,
        "category": "scam_lottery"
    }
]

# Real-world legitimate email templates across corporate, personal, and transactional categories
LEGITIMATE_TEMPLATES = [
    {
        "subject": "Sprint Retrospective & Demo - Friday 3 PM",
        "sender": "sarah.jenkins@acme-corp.com",
        "body": "Hi team,\n\nA quick reminder that our bi-weekly Sprint 42 retrospective and demo will take place this Friday at 3:00 PM in Conference Room B and over Google Meet.\n\nPlease update your Jira tickets and add any discussion points or action items to the shared Notion retrospective board beforehand.\n\nLooking forward to seeing the new search latency improvements!\n\nBest regards,\nSarah Jenkins\nEngineering Lead | Acme Corporation",
        "label": 0,
        "category": "workplace"
    },
    {
        "subject": "GitHub: [Pull Request #342] Add health check endpoint and database pooling",
        "sender": "notifications@github.com",
        "body": "Hi harsh,\n\nAlex Mercer has approved pull request #342: 'Add health check endpoint and database connection pooling' on repository org/mailguard-service.\n\nReview comments:\n'Looks solid! Clean separation between DB pool initialization and shutdown handlers. Verified unit tests pass.'\n\nYou can merge this pull request directly on GitHub:\nhttps://github.com/org/mailguard-service/pull/342\n\nGitHub, Inc. 88 Colin P Kelly Jr St, San Francisco, CA 94107",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "Your monthly statement is ready to view - Chase Online",
        "sender": "no-reply@chase.com",
        "body": "Hello valued customer,\n\nYour latest credit card statement for account ending in 1092 covering the billing cycle ending October 28 is now available in your online banking portal.\n\nAccount Summary:\nNew Balance: $412.30\nMinimum Payment: $25.00\nPayment Due Date: November 24, 2026\n\nTo view your statement or manage paperless settings, log in securely at chase.com or use the official Chase Mobile app.\n\nJPMorgan Chase Bank, N.A. Member FDIC.",
        "label": 0,
        "category": "financial_legit"
    },
    {
        "subject": "Google Cloud: Monthly billing statement for project prod-cluster-01",
        "sender": "cloud-billing@google.com",
        "body": "Hello Cloud Administrator,\n\nYour monthly billing statement for billing account 0184A2-99B12 is now finalized. Your total charge of $128.45 has been automatically applied to your credit card ending in 8841.\n\nYou can review invoice breakdown, budget alerts, and resource utilization reports in the Google Cloud Console.\n\nGoogle LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "Weekend hiking plans - Bear Mountain trip",
        "sender": "david.morales88@gmail.com",
        "body": "Hey Harsh,\n\nHope you had a productive week! Are you still up for hiking Bear Mountain this Saturday? The weather forecast looks clear and around 65 degrees.\n\nI was thinking we could meet at the trailhead parking lot around 8:30 AM before it gets crowded. Let me know if that time works or if you want to carpool.\n\nTalk soon,\nDavid",
        "label": 0,
        "category": "personal"
    },
    {
        "subject": "Invitation: Quarterly Architecture Review @ Tue Nov 25, 2026 10am - 11:30am (EST)",
        "sender": "calendar-notification@google.com",
        "body": "You have been invited to the following event:\n\nQuarterly Architecture Review\nWhen: Tuesday Nov 25, 2026 10:00am - 11:30am Eastern Time\nWhere: https://meet.google.com/xyz-abcd-efg\nOrganizer: Priya Sharma (priya.s@techinnovations.io)\n\nAgenda:\n1. Microservices migration status\n2. Caching layer benchmarks (Redis vs Memcached)\n3. Threat modeling & SOC2 compliance checklist\n\nPlease confirm your attendance via the calendar buttons.",
        "label": 0,
        "category": "workplace"
    },
    {
        "subject": "Your Amazon.com order has shipped! (Order #112-9023812-4019283)",
        "sender": "shipment-tracking@amazon.com",
        "body": "Hello Harsh,\n\nGood news! Your order of 'Anker USB-C Fast Charger 65W' has shipped and will arrive tomorrow by 8 PM.\n\nCarrier: USPS Tracking ID: 940011189922312093812\nTrack your package anytime from your Amazon orders page at amazon.com/orders.\n\nThanks for shopping with Amazon!",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "Python Software Foundation Newsletter - Issue 248",
        "sender": "newsletter@python.org",
        "body": "Welcome to the latest edition of the Python Weekly Digest!\n\nHighlights this week:\n- Python 3.13 performance improvements: free-threaded CPython updates\n- Building modern async web apps with FastAPI and Pydantic v2\n- PyCon 2027 call for proposals is now officially open\n\nRead the full newsletter online at python.org/news.\nTo unsubscribe, click the link in your account preferences.",
        "label": 0,
        "category": "newsletter"
    },
    {
        "subject": "Slack notification: New mentions in #ml-platform",
        "sender": "notifications@slack.com",
        "body": "Elena Rostova mentioned you in #ml-platform:\n\n'@harsh - could you take a look at the model evaluation latency metrics on the staging cluster? We saw a 15% drop in inference time with the quantized weights.'\n\nReply directly in Slack or launch the desktop app to participate.",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "Notes from our 1:1 sync and next quarter priorities",
        "sender": "marcus.vance@acme-corp.com",
        "body": "Hey Harsh,\n\nThanks for the great conversation earlier today. Summarizing our key takeaways:\n\n- Goal 1: Finalize feature pipeline and model training benchmarking\n- Goal 2: Deliver real-time explainability dashboard for security operations\n- Goal 3: Complete comprehensive test suite with 90%+ code coverage\n\nLet me know if I missed anything. Have a great evening!\n\nMarcus",
        "label": 0,
        "category": "workplace"
    },
    {
        "subject": "LinkedIn: 3 people viewed your profile this week",
        "sender": "messages-noreply@linkedin.com",
        "body": "Hi Harsh,\n\nSee who has been checking out your profile this week, including professionals from Google, Microsoft, and Stripe.\n\nKeep your skills and experience up to date to increase visibility to recruiters.\n\nLinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "Flight Confirmation: San Francisco (SFO) to Seattle (SEA)",
        "sender": "confirmations@alaskaair.com",
        "body": "Your flight is confirmed!\n\nConfirmation Code: L83K9D\nPassenger: Harsh Sharma\nFlight: AS 1284 | Departing SFO 08:45 AM | Arriving SEA 10:55 AM\nSeat: 12A (Window)\n\nCheck in online 24 hours prior to departure at alaskaair.com.",
        "label": 0,
        "category": "transactional"
    },
    {
        "subject": "HR Notice: Open Enrollment for 2027 Benefits Begins Next Monday",
        "sender": "benefits-team@acme-corp.com",
        "body": "Dear Acme Team,\n\nAnnual open enrollment for medical, dental, vision, and 401(k) benefits opens Monday, November 24 and closes Friday, December 5.\n\nPlease attend the informational webinars hosted by our HR benefits advisory team or review the plan comparison documents on our internal intranet.\n\nAcme People Operations",
        "label": 0,
        "category": "workplace"
    },
    {
        "subject": "Substack: The Pragmatic Engineer - Scaling ML Pipelines",
        "sender": "pragmaticengineer@substack.com",
        "body": "Today's deep dive covers how top tech companies architect high-throughput machine learning inference pipelines with low latency SLAs.\n\nKey sections:\n- Model serving architectures (Triton, TorchServe, FastAPI)\n- Feature stores and low-latency cache invalidation\n- Drift monitoring in production environments\n\nEnjoy the issue!",
        "label": 0,
        "category": "newsletter"
    },
    {
        "subject": "Spotify: Your 2026 Year in Review is almost here!",
        "sender": "no-reply@spotify.com",
        "body": "Get ready! Your personalized Spotify Wrapped is arriving soon.\n\nWe are tallying your top songs, favorite artists, and podcast binge hours from the past year. Keep streaming to finalize your top playlist.\n\nListen on Spotify.",
        "label": 0,
        "category": "transactional"
    }
]


# Data synthesis and augmentation rules to scale the dataset with realistic variations
def augment_text(text: str, is_phish: bool) -> str:
    """Generate realistic adversarial variations and text diversity."""
    augmented = text
    
    if is_phish and random.random() < 0.4:
        # Inject realistic obfuscations common in phishing
        obfuscations = [
            ("paypal", "paypa1"),
            ("verify", "v3rify"),
            ("account", "acc0unt"),
            ("security", "s3curity"),
            ("update", "upd4te"),
            ("password", "p@ssword"),
            ("microsoft", "m1crosoft"),
        ]
        chosen = random.choice(obfuscations)
        if chosen[0] in augmented.lower():
            pattern = re.compile(re.escape(chosen[0]), re.IGNORECASE)
            augmented = pattern.sub(chosen[1], augmented, count=1)
            
    if is_phish and random.random() < 0.3:
        # Add urgent deadlines or financial hooks
        hooks = [
            "\n\nACT NOW: Verification period expires in 12 hours.",
            "\n\nImmediate response required to avoid administrative suspension.",
            "\n\nNote: Failure to comply constitutes immediate breach of policy.",
            "\n\nDO NOT CLOSE THIS PAGE UNTIL COMPLETE."
        ]
        augmented += random.choice(hooks)
    elif not is_phish and random.random() < 0.3:
        # Add normal conversational signatures
        signatures = [
            "\n\nThanks,\nTeam",
            "\n\nBest,\nSupport Engineering",
            "\n\nLet me know if you have questions.",
            "\n\nCheers,\nOperations"
        ]
        augmented += random.choice(signatures)
        
    return augmented


def generate_bundled_dataset(target_samples: int = 500) -> pd.DataFrame:
    """
    Generate a balanced, high-quality sample dataset containing phishing and legitimate emails.
    Includes rich subjects, senders, body content, categories, and labels.
    """
    random.seed(42)
    records: List[Dict[str, any]] = []
    
    # 1. Base seed records
    for item in PHISHING_TEMPLATES:
        records.append({
            "email_id": f"phish_{len(records):04d}",
            "subject": item["subject"],
            "sender": item["sender"],
            "body": item["body"],
            "full_text": f"Subject: {item['subject']}\nFrom: {item['sender']}\n\n{item['body']}",
            "label": 1,
            "category": item["category"]
        })
        
    for item in LEGITIMATE_TEMPLATES:
        records.append({
            "email_id": f"legit_{len(records):04d}",
            "subject": item["subject"],
            "sender": item["sender"],
            "body": item["body"],
            "full_text": f"Subject: {item['subject']}\nFrom: {item['sender']}\n\n{item['body']}",
            "label": 0,
            "category": item["category"]
        })
        
    # 2. Synthesize variations to scale up to target_samples with high quality
    phish_seeds = [t for t in PHISHING_TEMPLATES]
    legit_seeds = [t for t in LEGITIMATE_TEMPLATES]
    
    variations_per_seed = (target_samples - len(records)) // (len(phish_seeds) + len(legit_seeds)) + 1
    
    for i in range(variations_per_seed):
        for item in phish_seeds:
            if len([r for r in records if r["label"] == 1]) >= target_samples // 2:
                break
            aug_body = augment_text(item["body"], is_phish=True)
            aug_subject = item["subject"]
            if random.random() < 0.3:
                aug_subject = f"[URGENT] {aug_subject}"
            elif random.random() < 0.3:
                aug_subject = f"FWD: {aug_subject}"
                
            records.append({
                "email_id": f"phish_syn_{len(records):04d}",
                "subject": aug_subject,
                "sender": item["sender"],
                "body": aug_body,
                "full_text": f"Subject: {aug_subject}\nFrom: {item['sender']}\n\n{aug_body}",
                "label": 1,
                "category": item["category"]
            })
            
        for item in legit_seeds:
            if len([r for r in records if r["label"] == 0]) >= target_samples // 2:
                break
            aug_body = augment_text(item["body"], is_phish=False)
            aug_subject = item["subject"]
            if random.random() < 0.2:
                aug_subject = f"Re: {aug_subject}"
                
            records.append({
                "email_id": f"legit_syn_{len(records):04d}",
                "subject": aug_subject,
                "sender": item["sender"],
                "body": aug_body,
                "full_text": f"Subject: {aug_subject}\nFrom: {item['sender']}\n\n{aug_body}",
                "label": 0,
                "category": item["category"]
            })

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def ensure_dataset_ready(data_dir: str = "data/raw") -> str:
    """Ensure the bundled sample dataset exists on disk; creates it if missing."""
    os.makedirs(data_dir, exist_ok=True)
    output_path = os.path.join(data_dir, "bundled_samples.csv")
    if not os.path.exists(output_path):
        print(f"[*] Generating bundled sample dataset at {output_path}...")
        df = generate_bundled_dataset(target_samples=400)
        df.to_csv(output_path, index=False)
        print(f"[+] Successfully wrote {len(df)} samples ({df['label'].value_counts().to_dict()}) to {output_path}")
    else:
        print(f"[i] Dataset already exists at {output_path}")
    return output_path


if __name__ == "__main__":
    ensure_dataset_ready()
