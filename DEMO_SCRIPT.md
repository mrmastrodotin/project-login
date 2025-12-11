# Live Security Demonstration Script

This script guides you through presenting the security features of **SecureApp**.

## Opening
**SAY:** "Thank you. Today I'm going to demonstrate how SecureApp uses a multi-layered defense system to protect user data. We will actively try to attack the system to show these defenses in action."

---

## Part 1: The Bot Trap (Honeypot)

**GOAL:** Show how we catch automated bots without annoying real users with CAPTCHAs.

**SAY:** "First, let's look at Bot Protection. Most spam bots look for every field in a form and fill it out. We have a hidden trap waiting for them."

**ACTION:**
1.  Open the **Register** page.
2.  Right-click on the form and select **Inspect** (Open Developer Tools).
3.  Find the input field with `name="bot_catcher"` (It might be near the Password fields).
4.  **SAY:** "Here is a hidden field called 'Middle Name'. Real users can't see it, but bots will find it in the code and fill it."
5.  In the Inspector, delete `style="display:none"` (or `class="hidden"`) to reveal the field.
6.  Type "I am a bot" into the Middle Name field.
7.  Fill out the rest of the form with dummy data (e.g., User: `Bot1`, Email: `bot@spam.com`, Pass: `123`).
8.  Click **Sign Up**.

**RESULT:**
- You are redirected to the Login page with a "Success" message.
- **SAY:** "The system pretends to succeed so the bot doesn't know it was caught."
- **ACTION:** Try to Login with those credentials (`bot@spam.com` / `123`).
- **RESULT:** "Login Unsuccessful".
- **SAY:** "But in reality, the account was never created. The bot was silently rejected."

---

## Part 2: The Brute Force Block (Rate Limiting)

**GOAL:** Show how we stop hackers from guessing passwords millions of times.

**SAY:** "Next, let's try a Brute Force attack. I will try to guess a user's password repeatedly."

**ACTION:**
1.  Go to the **Login** page.
2.  Enter a valid email (e.g., any email) but a **WRONG** password.
3.  Click **Login** (Attempt 1).
4.  **SAY:** "Attempt 1... Attempt 2..."
5.  Quickly repeat this 5 times.
6.  On the 6th or 7th attempt...

**RESULT:**
- You see a **429 Too Many Requests** error page (or message).
- **SAY:** "And there we go. The system detected the attack pattern and blocked my IP address. This makes brute force attacks impossible."

---

## Part 3: The Vault (Secure Storage)

**GOAL:** Show that even if the database is stolen, passwords are safe.

**SAY:** "Finally, what if a hacker steals our entire database?"

**ACTION:**
1.  Open your terminal.
2.  Run the verification script: `python verify_security.py`
3.  Point to the output under `[1] TEST: Password Hashing`.
4.  **SAY:** "Here is what our database actually looks like. The password is not stored as 'password123', but as a complex cryptographic hash."
5.  **SAY:** "This means even we don't know your password. Only you do."

---

## Closing
**SAY:** "By combining these three layers—Honeypots, Rate Limiting, and Encryption—SecureApp ensures your data remains safe from the most common modern threats. Thank you."
