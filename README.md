# DocuScan

**DocuScan** is a cutting-edge web application that transforms document scanning and matching into a sleek, AI-powered experience. Built from scratch with a stunning UI, it’s packed with features like user authentication, a credit system, Google Gemini AI matching, and a dynamic admin dashboard—all wrapped in a visually jaw-dropping design.

---

## Features

### Core Functionality
- **User Authentication**: Secure registration and login with SHA-256 hashed passwords. Two roles: Users (0) and Admins (1).
- **Credit System**: 
  - 20 free scans per day for users, auto-resetting at midnight (server time).
  - Users can request additional credits; admins approve/deny via a slick interface.
- **Document Scanning**: 
  - Users upload `.txt` files (1 credit per scan).
  - Admins upload unlimited `.txt` files—no credit cost.
- **AI-Powered Matching**: Leverages Google Gemini (`embedding-001`) for semantic similarity detection (20% threshold), with a fallback to word frequency matching if the API fails.
- **Smart Analytics**: A futuristic admin dashboard tracks scans per user (last 24h), top keywords, top users, and total approved credits.

### Bonus Features
- **Automated Credit Reset**: Credits refresh daily at midnight—seamless and automatic.
- **Activity Logs**: Every action (scans, credit requests, approvals) logged in `logs/activity.log` for transparency.
- **Dynamic Dashboard**: A visually stunning “System Control Hub” with animated stats and interactive panels—admin’s dream.
- **Export Reports**: Users can download their scan history as a `.txt` file with one click.
- **Multi-user Support**: Handles concurrent users flawlessly via Flask sessions and SQLite.

### UI Highlights
- **Eye-Catching Landing Page**: Bold hero section with gradient background, punchy tagline, and standout CTA buttons.
- **Sleek Forms & Buttons**: Modern, shadowed cards with glowing inputs and gradient, pill-shaped buttons that pop.
- **Stunning Dashboard**: Dark, system-like design with pulsing stats, lifting panels, and a premium feel.

---

## Tech Stack

- **Frontend**: HTML, CSS (custom), JavaScript (vanilla)—no frameworks, pure craftsmanship.
- **Backend**: Python with Flask—lightweight and powerful.
- **Database**: SQLite—portable and embedded.
- **File Storage**: Local `uploads/` directory for document storage.
- **AI Matching**: Google Gemini API (optional, with fallback to custom word frequency).
- **Logging**: Python `logging` for activity tracking.
- **Styling**: Custom CSS with `Inter` font (Google Fonts)—modern and cohesive.

---

## Prerequisites

- **Python**: 3.x (tested with 3.9+)
- **Dependencies**: 
  - Flask (`pip install flask`)
  - Requests (`pip install requests`)—for Gemini API
- **Google Gemini API Key**: Required for AI matching (optional; falls back if unavailable).

---

## Installation & Setup

Follow these steps to get DocuScan running locally:

### Step 1: Clone the Repository
```bash
git clone <repository-url>
```
### Step 2: Change the Directory
```bash
cd DocuScan
```
### Step 3: Install the dependencies
```bash
pip install flask requests
```
### Step 4: Run the file
```bash
python app.py
