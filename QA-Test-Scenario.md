# QA Manual Test Scenarios - Mailria Platform

**Document Version**: 1.0
**Date**: 2026-02-14
**Application**: Mailria Email Platform (Frontend)
**Tech Stack**: Next.js 15, React 19, Zustand, Axios, TinyMCE

---

## Table of Contents

1. [Login & Authentication](#1-login--authentication)
2. [Forgot Password Flow](#2-forgot-password-flow)
3. [User (Role 1) Features](#3-user-role-1-features)
4. [Admin (Role 2) Features](#4-admin-role-2-features)
5. [SuperAdmin (Role 0) Features](#5-superadmin-role-0-features)
6. [Role-Based Access Control](#6-role-based-access-control)
7. [Token & Session Management](#7-token--session-management)
8. [Edge Cases Already Handled](#8-edge-cases-already-handled)
9. [Edge Cases NOT Covered](#9-edge-cases-not-covered-gaps)

---

## 1. Login & Authentication

### 1.1 Basic Login

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| L-01 | Login with valid User credentials | Enter valid email + password → Click Login | Redirect to `/inbox` |
| L-02 | Login with valid Admin credentials | Enter valid admin email + password → Click Login | Redirect to `/admin/overview` |
| L-03 | Login with valid SuperAdmin credentials | Enter valid superadmin email + password → Click Login | Redirect to `/admin/overview` |
| L-04 | Login with invalid email | Enter wrong email + any password → Click Login | Error toast: "Invalid email or password" |
| L-05 | Login with invalid password | Enter valid email + wrong password → Click Login | Error toast: "Invalid email or password" |
| L-06 | Login with empty email | Leave email empty → Click Login | Form validation prevents submission |
| L-07 | Login with empty password | Leave password empty → Click Login | Form validation prevents submission |
| L-08 | Login with both fields empty | Click Login with both fields empty | Form validation prevents submission |
| L-09 | Show/hide password toggle | Click eye icon on password field | Password text toggles between visible and masked |
| L-10 | Remember Me - checked | Check "Remember me" → Login → Close browser → Reopen | User stays logged in |
| L-11 | Remember Me - unchecked | Uncheck "Remember me" → Login → Close browser → Reopen | User must login again |

### 1.2 Account Lockout

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| L-12 | Account lockout after failed attempts | Enter wrong password multiple times until locked | Shows lockout message with countdown timer (5 min) |
| L-13 | Login during lockout | Try to login while account is locked | Login button disabled, countdown timer displayed |
| L-14 | Login after lockout expires | Wait for lockout timer to expire → Login with correct credentials | Login succeeds |

### 1.3 Input Sanitization

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| L-15 | XSS in email field | Enter `<script>alert('xss')</script>` in email | Input sanitized via DOMPurify, no script execution |
| L-16 | XSS in password field | Enter script tags in password | Input sanitized, no script execution |
| L-17 | Whitespace in email | Enter ` user@mail.com ` (with spaces) | Whitespace trimmed before submission |
| L-18 | Whitespace in password | Enter ` password ` (with spaces) | Whitespace trimmed before submission |

---

## 2. Forgot Password Flow

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| FP-01 | Navigate to forgot password | Click "Forgot password?" link on login page | Redirects to `/forgot-password` |
| FP-02 | Submit valid email | Enter registered email → Click Submit | OTP verification step appears |
| FP-03 | Submit unregistered email | Enter non-existent email → Click Submit | Error message displayed |
| FP-04 | Verify with valid OTP | Enter correct OTP code → Submit | Proceeds to reset password step |
| FP-05 | Verify with invalid OTP | Enter wrong OTP code → Submit | Error message: invalid code |
| FP-06 | Reset password with valid input | Enter new password + confirm matching → Submit | Success → Redirect to login with success toast |
| FP-07 | Reset password mismatch | Enter mismatched passwords → Submit | Error: passwords don't match |
| FP-08 | Reset password too short | Enter password < 6 characters | Error: minimum 6 characters |
| FP-09 | Success toast on redirect | Complete reset → Redirected to login with `?reset=success` | Green toast: "Password reset successful" |

---

## 3. User (Role 1) Features

### 3.1 Inbox

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| U-01 | View inbox | Login as User → Land on `/inbox` | Email list displayed with sender, subject, date |
| U-02 | View email detail | Click on an email in inbox list | Email detail view opens with full content |
| U-03 | Mark email as read | Click on unread email | Email marked as read (visual indicator changes) |
| U-04 | Delete email | Click delete on an email → Confirm | Email removed from inbox |
| U-05 | Search inbox | Type keyword in search bar | Filtered results displayed |
| U-06 | Empty inbox | User has no emails | Empty state icon + message shown |
| U-07 | Manual refresh | Click refresh button | Inbox reloads, spinner shown during fetch |
| U-08 | Auto-refresh (active) | Stay on inbox page for 60+ seconds | Inbox auto-refreshes every 60 seconds |
| U-09 | Auto-refresh (idle) | Leave inbox page idle for 5+ minutes | Auto-refresh stops after 5 min inactivity |
| U-10 | Auto-refresh (resume) | Return from idle (move mouse/type) | Auto-refresh resumes on activity |
| U-11 | Auto-refresh (background tab) | Switch to another browser tab | Auto-refresh pauses when tab is not visible |

### 3.2 Compose & Send Email

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| U-12 | Open compose modal | Click compose/new email button | Compose modal opens |
| U-13 | Send email with all fields | Fill To, Subject, Body → Click Send | Email sent, success toast, modal closes |
| U-14 | Send without recipient | Leave "To" empty → Click Send | Validation error: recipient required |
| U-15 | Send without subject | Leave subject empty → Click Send | Validation error: subject required |
| U-16 | Attach files | Add attachments (< 10MB each, < 10 files) | Files attached, shown in attachment list |
| U-17 | Attach file over 10MB | Try to attach a file > 10MB | Error toast: file too large |
| U-18 | Attach more than 10 files | Try to add 11th attachment | Error toast: max 10 files |
| U-19 | Daily send limit reached | Send emails until daily quota hit (3/day) | Error shown with reset time |
| U-20 | Reply to email | Open email → Click Reply | Compose modal with quoted original email |
| U-21 | Forward email | Open email → Click Forward | Compose modal with forwarded content |
| U-22 | Rich text editor | Format text (bold, italic, lists) in TinyMCE | Formatting applied correctly |
| U-23 | Discard unsaved compose | Start composing → Click close | Confirmation dialog: discard changes? |

### 3.3 Sent View

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| U-24 | View sent emails | Navigate to Sent tab/view | List of sent emails displayed |
| U-25 | View sent email detail | Click on a sent email | Full email detail shown (recipient, subject, body) |
| U-26 | Empty sent | No emails sent yet | Empty state shown |

### 3.4 User Settings

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| U-27 | Change password - valid | Enter old password + new password (6+ chars) + confirm → Submit | Password changed, success toast |
| U-28 | Change password - wrong old | Enter incorrect old password | Error: incorrect current password |
| U-29 | Change password - mismatch | New password ≠ confirm password | Error below field: passwords don't match |
| U-30 | Change password - too short | New password < 6 characters | Error: minimum 6 characters |
| U-31 | Email binding | Set up alternate email for recovery | Binding email saved |
| U-32 | View account info | Navigate to settings | Account email and info displayed |

---

## 4. Admin (Role 2) Features

### 4.1 Dashboard Overview

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-01 | View dashboard KPIs | Login as Admin → Navigate to Overview | KPI cards: total mailria users, mailsaja users, inbox count, sent count |
| A-02 | View latest inbox | Check "Latest Inbox" section on dashboard | 5 most recent inbox emails displayed |
| A-03 | View latest sent | Check "Latest Sent" section on dashboard | 5 most recent sent emails displayed |
| A-04 | Refresh dashboard | Click refresh button | All KPIs and lists reload |

### 4.2 User Management

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-05 | View user list | Navigate to User list | Paginated list (10/page) with email, last active, actions |
| A-06 | Search users | Type email keyword in search bar | Filtered results, page resets to 1 |
| A-07 | Sort by last active | Select "Last active" sort option | List sorted by last activity |
| A-08 | Sort by created date | Select "Created date" sort option | List sorted by creation date |
| A-09 | Pagination | Navigate between pages | Correct page data loaded |
| A-10 | View user detail | Click "View" on a user | Opens user detail/inbox view |
| A-11 | Change user password | Click "Change Password" → Enter new password (6+ chars) → Submit | Password updated, success toast |
| A-12 | Change user password - too short | Enter password < 6 characters | Validation error |
| A-13 | Delete user | Click "Delete" → Confirm in dialog | User removed, list refreshed |
| A-14 | Delete user - cancel | Click "Delete" → Click cancel in dialog | User not deleted, dialog closes |
| A-15 | Last active badge | Check last active column | Shows "Online" / "X min ago" / "X hours ago" / "X days ago" |
| A-16 | Active user count | Check active users display | Count displayed correctly |

### 4.3 Create Single Email Account

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-17 | Create valid account | Enter username + select domain + set password → Create | Account created, result card with email + password |
| A-18 | Copy email | Click copy icon on email in result card | Email copied, "Copied!" feedback (2s) |
| A-19 | Copy password | Click copy icon on password in result card | Password copied, "Copied!" feedback (2s) |
| A-20 | Random password | Click random/generate password button | Random password generated |
| A-21 | Empty username | Leave username empty → Create | Validation error |
| A-22 | Password too short | Enter password < 6 characters → Create | Validation error |

### 4.4 Create Bulk Email Accounts

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-23 | Create bulk accounts | Enter base username + domain + quantity + password length → Create | Accounts created (user001, user002, etc) |
| A-24 | Export CSV | After bulk creation → Click export | CSV file downloaded with all created accounts |
| A-25 | Send to email (CC) | Fill "Send to email" → Create bulk | Results also sent to specified email |
| A-26 | Loading state | Click Create for bulk operation | Loading spinner shown during creation |

### 4.5 All Inbox (Admin View)

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-27 | View all users' inbox | Navigate to All Inbox | All emails across all users displayed |
| A-28 | Search all inbox | Enter search term | Filtered results |
| A-29 | View email detail (admin) | Click on an email | Full email content shown |

### 4.6 All Sent (Admin View)

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-30 | View all sent emails | Navigate to All Sent | All sent emails across all users displayed |
| A-31 | Search all sent | Enter search term | Filtered results |

### 4.7 Terms & Privacy Policy

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-32 | View Terms of Service | Navigate to Terms page | Current terms displayed in editor |
| A-33 | Edit Terms of Service | Modify content in TinyMCE → Save | Changes saved, success toast |
| A-34 | View Privacy Policy | Navigate to Privacy page | Current privacy policy displayed |
| A-35 | Edit Privacy Policy | Modify content in TinyMCE → Save | Changes saved, success toast |

### 4.8 Admin Settings

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| A-36 | Change admin password | Enter old + new (6+ chars) + confirm → Submit | Password changed |
| A-37 | Password mismatch | New ≠ confirm | Error: passwords don't match |
| A-38 | Wrong old password | Enter incorrect old password | Error displayed |

---

## 5. SuperAdmin (Role 0) Features

### 5.1 Roles & Permissions Management

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| SA-01 | View admin users list | Navigate to Roles & Permissions | List of all admin users with permissions |
| SA-02 | Create admin account | Fill username + password + select permissions → Create | Admin account created |
| SA-03 | Create admin - show/hide password | Toggle password visibility during creation | Password toggles masked/visible |
| SA-04 | Edit admin permissions | Click edit on admin user → Modify permissions → Save | Permissions updated |
| SA-05 | Delete admin account | Click delete → Confirm | Admin removed from list |
| SA-06 | Permission multi-select | Select/deselect permissions during create/edit | Chips update to reflect selections |
| SA-07 | SuperAdmin has all permissions | Login as SuperAdmin → Check sidebar | All menu items visible |
| SA-08 | Admin last active tracking | Check last active column for admins | Correct activity timestamps |

---

## 6. Role-Based Access Control

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| RBAC-01 | User cannot access admin routes | Login as User → Navigate to `/admin/overview` | Redirected to `/not-found` |
| RBAC-02 | Admin cannot access user inbox | Login as Admin → Navigate to `/inbox` | Redirected to `/not-found` |
| RBAC-03 | Admin without permission | Login as Admin (no `overview` permission) → Try to access Overview | Menu item hidden / access denied |
| RBAC-04 | Admin sidebar respects permissions | Login as Admin with limited permissions | Only permitted menu items shown |
| RBAC-05 | SuperAdmin sees all menu items | Login as SuperAdmin → Check sidebar | All items visible including "Roles & Permissions" |
| RBAC-06 | Regular Admin cannot see Roles | Login as Admin (role 2) → Check sidebar | "Roles & Permissions" menu item hidden |
| RBAC-07 | Unauthenticated user access | Visit `/inbox` without login | Redirected to `/` (login page) |
| RBAC-08 | Unauthenticated admin access | Visit `/admin/overview` without login | Redirected to login |

---

## 7. Token & Session Management

| # | Test Scenario | Steps | Expected Result |
|---|---------------|-------|-----------------|
| TK-01 | Token stored on login | Login successfully → Check localStorage | `auth-storage` key contains token, refreshToken, etc. |
| TK-02 | Token refresh on 401 | Wait for token to expire → Make API call | Token auto-refreshed, request retried |
| TK-03 | Refresh token failure | Invalidate refresh token → Make API call | Logged out, redirected to login |
| TK-04 | Multiple requests during refresh | Trigger multiple API calls with expired token | Requests queued and retried after refresh |
| TK-05 | Logout clears storage | Click logout | localStorage + sessionStorage cleared, redirect to `/` |
| TK-06 | Hydration state | Refresh page | Loading shown until Zustand hydrates from localStorage |

---

## 8. Edge Cases Already Handled

These edge cases are implemented in the codebase and should pass testing:

| Category | Edge Case | Implementation |
|----------|-----------|----------------|
| **Auth** | Account lockout countdown | `LoginPageClient.tsx` - Parses `blocked_until`, shows timer |
| **Auth** | Token refresh with request queuing | `api-client.ts` - Queues failed 401 requests during refresh |
| **Auth** | SSR hydration mismatch | `useAuthStore.ts` - `_hasHydrated` flag prevents rendering before hydration |
| **Auth** | XSS via login inputs | `LoginPageClient.tsx` - DOMPurify sanitizes all inputs |
| **Email** | Auto-refresh stops on idle (5 min) | `InboxList.tsx` - Tracks mouse/keyboard/scroll/touch activity |
| **Email** | Auto-refresh pauses on hidden tab | `InboxList.tsx` - Listens to `visibilitychange` event |
| **Email** | Daily send limit enforcement | `ComposeModal.tsx` - Checks quota API, shows reset time |
| **Email** | File attachment limits | `ComposeModal.tsx` - Max 10 files, 10MB each |
| **Email** | Discard unsaved compose | `ComposeModal.tsx` - Confirmation dialog on close with changes |
| **UI** | Empty states | All list views - Shows icon + message when no data |
| **UI** | Loading skeletons | `InboxListSkeleton` and admin loaders - Skeleton screens during fetch |
| **UI** | Error boundary | `ErrorBoundary.tsx` - Catches component crashes, offers retry/refresh |
| **UI** | Mobile responsiveness | AdminSidebar/MobileNav - Desktop sidebar + mobile bottom tabs |
| **API** | Request timeout | `api-client.ts` - 30s timeout on all requests |
| **Admin** | Permission-based sidebar | `AdminSidebar.tsx` - Hides menu items without permission |
| **Admin** | SuperAdmin bypass | `useAuthStore.ts` - `hasPermission()` returns true for roleId=0 |
| **Admin** | Copy-to-clipboard feedback | Create email pages - "Copied!" state for 2 seconds |
| **Admin** | Password masking | All password fields - Dots with show/hide toggle |
| **Admin** | Password field cleared on modal close | Change password dialogs - Clears password state for security |
| **Form** | Password confirmation mismatch | Settings/change password - Red outline + error message |
| **Form** | Search debouncing | User list/inbox - Debounced search reduces API calls |
| **Form** | Reset to page 1 on search | User list - Pagination resets when search term changes |

---

## 9. Edge Cases NOT Covered (Gaps)

These are potential issues and missing test scenarios that are **not currently handled** in the frontend:

### 9.1 Authentication & Security Gaps

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-01 | **No CSRF protection on client** | HIGH | Auth tokens stored in localStorage (not HttpOnly cookies). Vulnerable to XSS-based token theft. |
| GAP-02 | **No session timeout / auto-logout** | HIGH | User stays logged in indefinitely if token doesn't expire. No forced logout after X hours of inactivity. Auto-refresh stops but session persists. |
| GAP-03 | **No concurrent session detection** | MEDIUM | User can login from multiple devices/browsers simultaneously. No "logged in from another device" warning. |
| GAP-04 | **No brute-force protection on forgot password** | MEDIUM | OTP verification doesn't appear to have rate limiting on the frontend. Relies entirely on backend. |
| GAP-05 | **No password strength indicator** | LOW | Only min 6 chars validated. No check for weak passwords (e.g., "123456", "password"). |
| GAP-06 | **Token visible in DevTools** | MEDIUM | Access token stored in plain text in localStorage. Any XSS vulnerability exposes tokens. |
| GAP-07 | **No "Log out all sessions" feature** | LOW | Admin/user cannot invalidate all active sessions from settings. |

### 9.2 User Experience Gaps

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-08 | **No offline handling** | MEDIUM | No detection of network disconnection. API calls fail silently or show generic errors. No "You are offline" banner. |
| GAP-09 | **No retry on network failure** | MEDIUM | If an API call fails due to network (not 401), there's no automatic retry or user-facing retry button per-request. |
| GAP-10 | **No email pagination** | LOW-MEDIUM | Inbox/sent lists may not paginate large volumes. Potential performance issues with thousands of emails. |
| GAP-11 | **No confirmation before delete email** | MEDIUM | Email delete may happen immediately without "Are you sure?" dialog (soft delete on UI side). |
| GAP-12 | **No undo delete** | LOW | Once email is deleted, there's no undo/trash mechanism. |
| GAP-13 | **No draft auto-save** | MEDIUM | If browser crashes while composing, email content is lost. No periodic auto-save to localStorage. |
| GAP-14 | **No multi-select / bulk email actions** | LOW | Cannot select multiple emails to delete/mark as read in bulk. |

### 9.3 Admin Feature Gaps

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-15 | **No direct URL protection for admin sub-pages** | HIGH | AdminLayout checks token + role, but if an Admin (role 2) manually types `/admin/roles` URL, the frontend guard may not block at the route level (only sidebar hides it). |
| GAP-16 | **No audit log** | MEDIUM | Admin actions (delete user, change password, edit terms) are not logged. No traceability. |
| GAP-17 | **No bulk delete users** | LOW | Admin must delete users one by one. No multi-select delete. |
| GAP-18 | **No duplicate username check on create** | MEDIUM | When creating single/bulk accounts, there's no pre-check if username already exists. Relies on backend error. |
| GAP-19 | **No export/download user list** | LOW | Cannot export full user list to CSV (only bulk-created users). |
| GAP-20 | **No confirmation before editing Terms/Privacy** | MEDIUM | Rich text editor saves directly. No "unsaved changes" warning if navigating away. |

### 9.4 Input Validation Gaps

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-21 | **No email format validation on compose** | MEDIUM | "To" field may not validate email format (e.g., accepts "notanemail"). |
| GAP-22 | **No max length on inputs** | LOW | Username, subject, and other text fields have no max character limit on FE. |
| GAP-23 | **No special character validation on username** | LOW | Username during account creation may accept special characters that backend rejects. |
| GAP-24 | **No file type restriction on attachments** | LOW | All file types accepted. No block for potentially dangerous files (.exe, .bat, .sh). |

### 9.5 Accessibility & UX Gaps

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-25 | **Limited ARIA labels** | MEDIUM | Screen readers may not properly navigate the application. Buttons/icons lack `aria-label`. |
| GAP-26 | **No keyboard navigation** | MEDIUM | Cannot navigate email list / admin tables with keyboard only. |
| GAP-27 | **No focus management** | LOW | After modal close or page transition, focus is not returned to triggering element. |
| GAP-28 | **No loading feedback for slow operations** | LOW | Long operations like bulk create show spinner but no progress indicator (e.g., "Creating 50/100 users..."). |

### 9.6 Browser & Edge Cases

| # | Gap | Risk Level | Description |
|---|-----|-----------|-------------|
| GAP-29 | **No localStorage full handling** | LOW | If localStorage is full, Zustand persist will fail silently. |
| GAP-30 | **No private/incognito mode handling** | LOW | Some browsers restrict localStorage in private mode. May cause auth failures. |
| GAP-31 | **No back button handling** | MEDIUM | After logout, pressing browser back button may show cached authenticated pages. |
| GAP-32 | **No deep link handling** | LOW | Sharing a direct URL to `/inbox/123` may not work correctly for unauthenticated users (should redirect to login then back to URL). |
| GAP-33 | **No multi-tab sync** | LOW | Logging out in one tab doesn't log out other tabs (no `storage` event listener). |
| GAP-34 | **No timezone handling for email timestamps** | LOW | Email dates may display in server timezone, not user's local timezone. |

---

## Test Priority Matrix

| Priority | Test Areas | Count |
|----------|-----------|-------|
| **P0 - Critical** | Login (L-01 to L-14), RBAC (RBAC-01 to RBAC-08), Token (TK-01 to TK-06) | ~28 |
| **P1 - High** | Compose & Send (U-12 to U-23), User Management (A-05 to A-16), Forgot Password (FP-01 to FP-09) | ~28 |
| **P2 - Medium** | Inbox (U-01 to U-11), Admin Create (A-17 to A-26), Settings (U-27 to U-32) | ~23 |
| **P3 - Low** | Sent View (U-24 to U-26), Terms/Privacy (A-32 to A-35), Dashboard (A-01 to A-04) | ~13 |

---

## Test Environment Setup

- **Browser**: Chrome (latest), Firefox (latest), Safari (latest), Edge (latest)
- **Devices**: Desktop (1920x1080), Tablet (768px), Mobile (375px)
- **Test Accounts Required**:
  - 1x SuperAdmin (roleId: 0)
  - 1x Admin with all permissions (roleId: 2)
  - 1x Admin with limited permissions (roleId: 2)
  - 2x Regular User (roleId: 1)
  - 1x Locked account (for lockout testing)
- **API Backend**: Running on `localhost:8000`

---